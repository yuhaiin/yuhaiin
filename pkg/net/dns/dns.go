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
	pdns "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lru"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"golang.org/x/net/dns/dnsmessage"
)

type Config struct {
	Type       pdns.Type
	IPv6       bool
	Subnet     netip.Prefix
	Name       string
	Host       string
	Servername string
	Dialer     proxy.Proxy
}

var dnsMap syncmap.SyncMap[pdns.Type, func(Config) (dns.DNS, error)]

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

func Register(tYPE pdns.Type, f func(Config) (dns.DNS, error)) {
	if f != nil {
		dnsMap.Store(tYPE, f)
	}
}

var _ dns.DNS = (*client)(nil)

type client struct {
	cache  *lru.LRU[string, ipResponse]
	do     func([]byte) ([]byte, error)
	config Config
	subnet []dnsmessage.Resource
	cond   syncmap.SyncMap[string, *struct {
		*sync.Cond
		Response dns.IPResponse
	}]
}

type ipResponse struct {
	ips         []net.IP
	expireAfter time.Time
}

func (c ipResponse) String() string {
	return fmt.Sprintf(`{ ips: %v }`, c.ips)
}

func NewClient(config Config, send func([]byte) ([]byte, error)) *client {
	c := &client{do: send, config: config, cache: lru.NewLru[string, ipResponse](100, 0)}

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

func (c *client) Do(b []byte) ([]byte, error) {
	if c.do == nil {
		return nil, fmt.Errorf("no dns process function")
	}

	return c.do(b)
}

func (c *client) LookupIP(domain string) ([]net.IP, error) {
	var aaaaerr error
	var aaaa dns.IPResponse
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
		resp = a.IPs()
	}

	if c.config.IPv6 {
		wg.Wait()
		if aaaaerr == nil {
			resp = append(resp, aaaa.IPs()...)
		}
	}

	if aerr != nil && (!c.config.IPv6 || aaaaerr != nil) {
		return nil, fmt.Errorf("lookup ip failed: aaaa: %v, a: %w", aaaaerr, aerr)
	}

	return resp, nil
}

func (c *client) Record(domain string, reqType dnsmessage.Type) (dns.IPResponse, error) {
	key := domain + reqType.String()

	if x, ok := c.cache.Load(key); ok {
		return dns.NewIPResponse(x.ips, uint32(time.Until(x.expireAfter).Seconds())), nil
	}

	lock := &struct {
		*sync.Cond
		Response dns.IPResponse
	}{Cond: sync.NewCond(&sync.Mutex{})}
	cond, ok := c.cond.LoadOrStore(key, lock)
	if ok {
		cond.L.Lock()
		cond.Wait()
		cond.L.Unlock()

		if cond.Response != nil {
			return cond.Response, nil
		}
		return nil, fmt.Errorf("can't get response of %s from cond", key)
	}

	defer c.cond.Delete(key)
	defer cond.Broadcast()

	ttl, resp, err := c.lookupIP(domain, reqType)
	if err != nil {
		return nil, fmt.Errorf("lookup %s, %v failed: %w", domain, reqType, err)
	}
	cond.Response = dns.NewIPResponse(resp, ttl)

	log.Debugf("%s lookup host [%s] %v success: {ips: %v, ttl: %d}\n", c.config.Name, domain, reqType, resp, ttl)

	expireAfter := time.Now().Add(time.Duration(ttl) * time.Second)
	c.cache.Add(key, ipResponse{resp, expireAfter}, lru.WithExpireTime(expireAfter))

	return cond.Response, nil
}

func (c *client) lookupIP(domain string, reqType dnsmessage.Type) (uint32, []net.IP, error) {
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
		return 0, nil, fmt.Errorf("pack dns message failed: %w", err)
	}

	d, err = c.Do(d)
	if err != nil {
		return 0, nil, fmt.Errorf("send dns message failed: %w", err)
	}

	p := &dnsmessage.Parser{}

	he, err := p.Start(d)
	if err != nil {
		return 0, nil, err
	}

	if he.ID != req.ID {
		return 0, nil, fmt.Errorf("id not match")
	}

	if he.RCode != dnsmessage.RCodeSuccess {
		return 0, nil, fmt.Errorf("rCode (%v) not success", he.RCode)
	}

	p.SkipAllQuestions()

	var ttl uint32
	i := make([]net.IP, 0)

	for {
		ip, ttL, err := resolveAOrAAAA(p, reqType)
		if err != nil {
			if errors.Is(err, dnsmessage.ErrSectionDone) {
				break
			}

			return 0, nil, err
		}
		if ip == nil {
			continue
		}

		// All Resources in a set should have the same TTL (RFC 2181 Section 5.2).
		if ttl == 0 || ttL < ttl {
			ttl = ttL
		}
		i = append(i, ip)
	}

	if len(i) == 0 {
		return 0, nil, ErrNoIPFound
	}
	return ttl, i, nil
}

var ErrNoIPFound = errors.New("no ip fond")

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
