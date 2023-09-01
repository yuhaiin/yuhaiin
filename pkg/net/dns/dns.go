package dns

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
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
	Dialer     netapi.Proxy
}

var dnsMap syncmap.SyncMap[pd.Type, func(Config) (netapi.Resolver, error)]

func New(config Config) (netapi.Resolver, error) {
	f, ok := dnsMap.Load(config.Type)
	if !ok {
		return nil, fmt.Errorf("no dns type %v process found", config.Type)
	}

	if config.Dialer == nil {
		config.Dialer = direct.Default
	}
	return f(config)
}

func Register(tYPE pd.Type, f func(Config) (netapi.Resolver, error)) {
	if f != nil {
		dnsMap.Store(tYPE, f)
	}
}

var _ netapi.Resolver = (*client)(nil)

type client struct {
	cache  *lru.LRU[string, []net.IP]
	send   func(context.Context, []byte) ([]byte, error)
	config Config
	subnet []dnsmessage.Resource
	cond   syncmap.SyncMap[string, *recordCond]
}

type recordCond struct {
	*sync.Cond
	ips []net.IP
	ttl uint32
}

func NewClient(config Config, send func(context.Context, []byte) ([]byte, error)) *client {
	c := &client{
		send:   send,
		config: config,
		cache:  lru.NewLru(lru.WithCapacity[string, []net.IP](100)),
	}

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

func (c *client) Do(ctx context.Context, _ string, b []byte) ([]byte, error) {
	if c.send == nil {
		return nil, fmt.Errorf("no dns process function")
	}

	return c.send(ctx, b)
}

func (c *client) LookupIP(ctx context.Context, domain string) ([]net.IP, error) {
	var aaaaerr error
	var aaaa []net.IP
	var wg sync.WaitGroup

	if c.config.IPv6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			aaaa, _, aaaaerr = c.Record(ctx, domain, dnsmessage.TypeAAAA)
		}()
	}

	resp, _, aerr := c.Record(ctx, domain, dnsmessage.TypeA)

	if c.config.IPv6 {
		wg.Wait()
		if aaaaerr == nil {
			resp = append(resp, aaaa...)
		}
	}

	if aerr != nil && (!c.config.IPv6 || aaaaerr != nil) {
		return nil, fmt.Errorf("lookup ip failed: aaaa: %w, a: %w", aaaaerr, aerr)
	}

	return resp, nil
}

var ErrCondEmptyResponse = errors.New("can't get response from cond")

func (c *client) Record(ctx context.Context, domain string, reqType dnsmessage.Type) ([]net.IP, uint32, error) {
	key := domain + reqType.String()

	if ips, expire, ok := c.cache.LoadExpireTime(key); ok {
		se := time.Until(expire).Seconds()
		if se < 0 {
			se = 0
		}
		return ips, uint32(se), nil
	}

	cond, ok := c.cond.LoadOrStore(key, &recordCond{Cond: sync.NewCond(&sync.Mutex{})})
	if ok {
		cond.L.Lock()
		cond.Wait()
		cond.L.Unlock()

		if len(cond.ips) != 0 {
			return cond.ips, cond.ttl, nil
		}
		return nil, 0, ErrCondEmptyResponse
	}

	defer func() {
		c.cond.Delete(key)
		cond.Broadcast()
	}()

	ips, ttl, err := c.lookupIP(ctx, domain, reqType)
	if err != nil {
		return ips, ttl, fmt.Errorf("lookup %s, %v failed: %w", domain, reqType, err)
	}

	cond.ips = ips
	cond.ttl = ttl

	log.Debug(
		"resolve domain",
		"resolver", c.config.Name,
		"host", domain,
		"type", reqType,
		"ips", ips,
		"ttl", ttl,
	)

	c.cache.Add(key, ips, lru.WithExpireTimeUnix(time.Now().Add(time.Duration(ttl)*time.Second)))

	return ips, ttl, nil
}

func (c *client) newRequest(domain string, reqType dnsmessage.Type) (uint16, []byte, error) {
	name, err := dnsmessage.NewName(domain + ".")
	if err != nil {
		return 0, nil, fmt.Errorf("parse domain failed: %w", err)
	}
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
				Name:  name,
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

	return req.ID, d, nil
}

func (c *client) lookupIP(ctx context.Context, domain string, reqType dnsmessage.Type) ([]net.IP, uint32, error) {
	id, d, err := c.newRequest(domain, reqType)
	if err != nil {
		return nil, 0, fmt.Errorf("pack dns message failed: %w", err)
	}

	d, err = c.Do(ctx, "", d)
	if err != nil {
		return nil, 0, fmt.Errorf("send dns message failed: %w", err)
	}

	p := &dnsmessage.Parser{}

	resp, err := p.Start(d)
	if err != nil {
		return nil, 0, err
	}

	if resp.ID != id {
		return nil, 0, fmt.Errorf("id not match")
	}

	if resp.RCode != dnsmessage.RCodeSuccess {
		return nil, 0, fmt.Errorf("rCode (%v) not success", resp.RCode)
	}

	if err := p.SkipAllQuestions(); err != nil {
		return nil, 0, fmt.Errorf("skip all questions failed: %w", err)
	}

	answers, err := p.AllAnswers()
	if err != nil {
		return nil, 0, err
	}

	if len(answers) == 0 {
		return nil, 0, ErrNoIPFound
	}

	var ttl uint32
	ips := make([]net.IP, 0, len(answers))

	for _, v := range answers {
		switch x := v.Body.(type) {
		case *dnsmessage.AResource:
			if reqType == dnsmessage.TypeA {
				ttl = v.Header.TTL
				ips = append(ips, net.IP(x.A[:]))
			}
		case *dnsmessage.AAAAResource:
			if reqType == dnsmessage.TypeAAAA {
				ttl = v.Header.TTL
				ips = append(ips, net.IP(x.AAAA[:]))
			}
		}
	}

	if ttl > 600 {
		ttl = 600
	}

	if len(ips) == 0 {
		return nil, 0, ErrNoIPFound
	}

	return ips, ttl, nil
}

var ErrNoIPFound = errors.New("no ip found")

func (c *client) Close() error { return nil }
