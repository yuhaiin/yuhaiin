package dns

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	pd "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lru"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"golang.org/x/net/dns/dnsmessage"
)

type Config struct {
	Type       pd.Type
	IPv6       bool
	Subnet     netip.Prefix
	Name       string
	Host       string
	Servername string
	Dialer     proxy.Proxy
}

var dnsMap syncmap.SyncMap[pd.Type, func(Config) (dns.DNS, error)]

func New(config Config) (dns.DNS, error) {
	f, ok := dnsMap.Load(config.Type)
	if !ok {
		return nil, fmt.Errorf("no dns type %v process found", config.Type)
	}

	if config.Dialer == nil {
		config.Dialer = direct.Default
	}
	return f(config)
}

func Register(tYPE pd.Type, f func(Config) (dns.DNS, error)) {
	if f != nil {
		dnsMap.Store(tYPE, f)
	}
}

var _ dns.DNS = (*client)(nil)

type client struct {
	cache  *lru.LRU[string, ipRecord]
	do     func([]byte) ([]byte, error)
	config Config
	subnet []dnsmessage.Resource
	cond   syncmap.SyncMap[string, *recordCond]
}

type recordCond struct {
	*sync.Cond
	Record dns.IPRecord
}

type ipRecord struct {
	ips         []net.IP
	expireAfter int64
}

func (c ipRecord) String() string {
	return fmt.Sprintf(`{ ips: %v, expireAfter: %d }`, c.ips, c.expireAfter)
}

func NewClient(config Config, send func([]byte) ([]byte, error)) *client {
	c := &client{do: send, config: config, cache: lru.NewLru[string, ipRecord](100, 0)}

	if !config.Subnet.IsValid() {
		return c
	}

	// EDNS Subnet
	optionData := bytes.NewBuffer(nil)

	ip := config.Subnet.Masked().Addr()
	if ip.Is6() { // family https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml
		optionData.Write([]byte{0b00000000, 0b00000010}) // family ipv6 2
	} else {
		optionData.Write([]byte{0b00000000, 0b00000001}) // family ipv4 1
	}

	mask := config.Subnet.Bits()
	optionData.WriteByte(byte(mask)) // mask
	optionData.WriteByte(0b00000000) // 0 In queries, it MUST be set to 0.

	var i int // cut the ip bytes
	if i = mask / 8; mask%8 != 0 {
		i++
	}

	optionData.Write(ip.AsSlice()[:i]) // subnet IP

	c.subnet = []dnsmessage.Resource{
		{
			Header: dnsmessage.ResourceHeader{
				Name:  dnsmessage.MustNewName("."),
				Type:  41,
				Class: 4096,
				TTL:   0,
			},
			Body: &dnsmessage.OPTResource{
				Options: []dnsmessage.Option{
					{
						Code: 8,
						Data: optionData.Bytes(),
					},
				},
			},
		},
	}
	return c
}

func (c *client) Do(_ string, b []byte) ([]byte, error) {
	if c.do == nil {
		return nil, fmt.Errorf("no dns process function")
	}

	return c.do(b)
}

func (c *client) LookupIP(domain string) ([]net.IP, error) {
	var aaaaerr error
	var aaaa dns.IPRecord
	var wg sync.WaitGroup

	if c.config.IPv6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			aaaa, aaaaerr = c.Record(domain, dnsmessage.TypeAAAA)
		}()
	}

	var resp []net.IP
	a, aerr := c.Record(domain, dnsmessage.TypeA)
	if aerr == nil {
		resp = a.IPs
	}

	if c.config.IPv6 {
		wg.Wait()
		if aaaaerr == nil {
			resp = append(resp, aaaa.IPs...)
		}
	}

	if aerr != nil && (!c.config.IPv6 || aaaaerr != nil) {
		return nil, fmt.Errorf("lookup ip failed: aaaa: %w, a: %w", aaaaerr, aerr)
	}

	return resp, nil
}

var ErrCondEmptyResponse = errors.New("can't get response from cond")

func (c *client) Record(domain string, reqType dnsmessage.Type) (dns.IPRecord, error) {
	key := domain + reqType.String()

	if x, ok := c.cache.Load(key); ok {
		return dns.IPRecord{IPs: x.ips, TTL: uint32(x.expireAfter - time.Now().Unix())}, nil
	}

	cond, ok := c.cond.LoadOrStore(key, &recordCond{Cond: sync.NewCond(&sync.Mutex{})})
	if ok {
		cond.L.Lock()
		cond.Wait()
		cond.L.Unlock()

		if len(cond.Record.IPs) != 0 {
			return cond.Record, nil
		}
		return dns.IPRecord{}, ErrCondEmptyResponse
	}

	defer func() {
		c.cond.Delete(key)
		cond.Broadcast()
	}()

	record, err := c.lookupIP(domain, reqType)
	if err != nil {
		return dns.IPRecord{}, fmt.Errorf("lookup %s, %v failed: %w", domain, reqType, err)
	}

	cond.Record = record

	log.Debugf("%s lookup host [%s] %v success: %v\n", c.config.Name, domain, reqType, record)

	expireAfter := time.Now().Unix() + int64(record.TTL)
	c.cache.Add(key, ipRecord{record.IPs, expireAfter}, lru.WithExpireTimeUnix(expireAfter))

	return record, nil
}

func (c *client) lookupIP(domain string, reqType dnsmessage.Type) (dns.IPRecord, error) {
	req := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 uint16(rand.Intn(65535)),
			Response:           false,
			OpCode:             0,
			Authoritative:      false,
			Truncated:          false,
			RecursionDesired:   true,
			RecursionAvailable: false,
			RCode:              0,
		},
		Questions: []dnsmessage.Question{
			{
				Name:  dnsmessage.MustNewName(domain + "."),
				Type:  reqType,
				Class: dnsmessage.ClassINET,
			},
		},
		Additionals: c.subnet,
	}

	d, err := req.Pack()
	if err != nil {
		return dns.IPRecord{}, fmt.Errorf("pack dns message failed: %w", err)
	}

	d, err = c.Do("", d)
	if err != nil {
		return dns.IPRecord{}, fmt.Errorf("send dns message failed: %w", err)
	}

	p := &dnsmessage.Parser{}

	resp, err := p.Start(d)
	if err != nil {
		return dns.IPRecord{}, err
	}

	if resp.ID != req.ID {
		return dns.IPRecord{}, fmt.Errorf("id not match")
	}

	if resp.RCode != dnsmessage.RCodeSuccess {
		return dns.IPRecord{}, fmt.Errorf("rCode (%v) not success", resp.RCode)
	}

	p.SkipAllQuestions()

	var ttl uint32
	ips := make([]net.IP, 0)

	for {
		ip, ttL, err := resolveAOrAAAA(p, reqType)
		if err != nil {
			if errors.Is(err, dnsmessage.ErrSectionDone) {
				break
			}

			return dns.IPRecord{}, err
		}
		if ip == nil {
			continue
		}

		// All Resources in a set should have the same TTL (RFC 2181 Section 5.2).
		if ttl == 0 || ttL < ttl {
			ttl = ttL
		}
		ips = append(ips, ip)
	}

	if len(ips) == 0 {
		return dns.IPRecord{}, ErrNoIPFound
	}
	return dns.IPRecord{IPs: ips, TTL: ttl}, nil
}

var ErrNoIPFound = errors.New("no ip found")

func (c *client) Close() error { return nil }

func resolveAOrAAAA(p *dnsmessage.Parser, reqType dnsmessage.Type) (net.IP, uint32, error) {
	header, err := p.AnswerHeader()
	if err != nil {
		return nil, 0, err
	}

	switch {
	case header.Type == dnsmessage.TypeA && reqType == dnsmessage.TypeA:
		body, err := p.AResource()
		if err != nil {
			return nil, 0, err
		}
		return net.IP(body.A[:]), header.TTL, nil
	case header.Type == dnsmessage.TypeAAAA && reqType == dnsmessage.TypeAAAA:
		body, err := p.AAAAResource()
		if err != nil {
			return nil, 0, err
		}
		return net.IP(body.AAAA[:]), header.TTL, nil
	default:
		err = p.SkipAnswer()
		if err != nil {
			return nil, 0, err
		}
	}

	return nil, 0, nil
}
