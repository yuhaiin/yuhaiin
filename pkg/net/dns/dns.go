package dns

import (
	"bytes"
	"container/list"
	"fmt"
	"log"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"golang.org/x/net/dns/dnsmessage"
)

type Config struct {
	Type       config.DnsDnsType
	Name       string
	Host       string
	Servername string
	Subnet     *net.IPNet
	IPv6       bool

	Dialer proxy.Proxy
}

var dnsMap syncmap.SyncMap[config.DnsDnsType, func(Config) dns.DNS]

func New(config Config) dns.DNS {
	f, ok := dnsMap.Load(config.Type)
	if !ok {
		return dns.NewErrorDNS(fmt.Errorf("no dns type %v process found", config.Type))
	}

	if config.Dialer == nil {
		config.Dialer = direct.Default
	}
	return f(config)
}

func Register(tYPE config.DnsDnsType, f func(Config) dns.DNS) {
	if f != nil {
		dnsMap.Store(tYPE, f)
	}
}

var _ dns.DNS = (*client)(nil)

type client struct {
	subnet []dnsmessage.Resource
	do     func([]byte) ([]byte, error)
	cache  *dnsLruCache[string, ipResponse]

	config Config
}

type ipResponse struct {
	ips         []net.IP
	expireAfter time.Time
}

func (c ipResponse) String() string {
	return fmt.Sprintf(`{ ips: %v]`, c.ips)
}

func NewClient(config Config, send func([]byte) ([]byte, error)) *client {
	c := &client{do: send, config: config, cache: newCache[string, ipResponse](300)}

	if config.Subnet != nil {
		optionData := bytes.NewBuffer(nil)

		mask, _ := config.Subnet.Mask.Size()
		ip := config.Subnet.IP.To4()
		if ip == nil { // family https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml
			optionData.Write([]byte{0b00000000, 0b00000010}) // family ipv6 2
			ip = config.Subnet.IP.To16()
		} else {
			optionData.Write([]byte{0b00000000, 0b00000001}) // family ipv4 1
		}
		optionData.WriteByte(byte(mask)) // mask
		optionData.WriteByte(0b00000000) // 0 In queries, it MUST be set to 0.

		i := mask / 8 // cut the ip bytes
		if mask%8 != 0 {
			i++
		}

		optionData.Write(ip[:i]) // subnet IP

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

	ttl, resp, err := c.lookupIP(domain, reqType)
	if err != nil {
		return nil, fmt.Errorf("lookup %s, %v failed: %w", domain, reqType, err)
	}

	log.Printf("%s lookup host [%s] %v success: {ips: %v, ttl: %d}\n",
		c.config.Name, domain, reqType, resp, ttl)

	expireAfter := time.Now().Add(time.Duration(ttl) * time.Second)

	c.cache.Add(key, ipResponse{resp, expireAfter}, expireAfter)
	return dns.NewIPResponse(resp, ttl), nil
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

	d, err = c.do(d)
	if err != nil {
		return 0, nil, fmt.Errorf("send dns message failed: %w", err)
	}

	var p dnsmessage.Parser
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
	i := make([]net.IP, 0, 1)

	for {
		header, err := p.AnswerHeader()
		if err != nil {
			if err == dnsmessage.ErrSectionDone {
				break
			}
			return 0, nil, err
		}

		// All Resources in a set should have the same TTL (RFC 2181 Section 5.2).
		ttl = header.TTL

		switch {
		case header.Type == dnsmessage.TypeA && reqType == dnsmessage.TypeA:
			body, err := p.AResource()
			if err != nil {
				return 0, nil, err
			}
			i = append(i, net.IP(body.A[:]))
		case header.Type == dnsmessage.TypeAAAA && reqType == dnsmessage.TypeAAAA:
			body, err := p.AAAAResource()
			if err != nil {
				return 0, nil, err
			}
			i = append(i, net.IP(body.AAAA[:]))
		default:
			err = p.SkipAnswer()
			if err != nil {
				return 0, nil, err
			}
		}
	}

	if len(i) == 0 {
		return 0, nil, fmt.Errorf("no ip found")
	}
	return ttl, i, nil
}

func (c *client) Close() error { return nil }

type cacheEntry[K, V any] struct {
	key        K
	data       V
	expireTime time.Time
}

//dnsLruCache Least Recently Used
type dnsLruCache[K, V any] struct {
	capacity int
	list     *list.List
	mapping  sync.Map
	lock     sync.Mutex
}

//newCache create new lru cache
func newCache[K, V any](capacity int) *dnsLruCache[K, V] {
	return &dnsLruCache[K, V]{
		capacity: capacity,
		list:     list.New(),
	}
}

func (l *dnsLruCache[K, V]) Add(key K, value V, expireTime time.Time) {
	l.lock.Lock()
	defer l.lock.Unlock()
	if elem, ok := l.mapping.Load(key); ok {
		r := elem.(*list.Element).Value.(*cacheEntry[K, V])
		r.key = key
		r.data = value
		r.expireTime = expireTime
		l.list.MoveToFront(elem.(*list.Element))
		return
	}

	if l.capacity == 0 || l.list.Len() < l.capacity {
		l.mapping.Store(key, l.list.PushFront(&cacheEntry[K, V]{
			key:        key,
			data:       value,
			expireTime: expireTime,
		}))
		return
	}

	elem := l.list.Back()
	r := elem.Value.(*cacheEntry[K, V])
	l.mapping.Delete(r.key)
	r.key = key
	r.data = value
	r.expireTime = expireTime
	l.list.MoveToFront(elem)
	l.mapping.Store(key, elem)
}

//Delete delete a key from cache
func (l *dnsLruCache[K, V]) Delete(key K) {
	l.mapping.LoadAndDelete(key)
}

func (l *dnsLruCache[K, V]) Load(key K) (v V, ok bool) {
	l.lock.Lock()
	defer l.lock.Unlock()
	node, ok := l.mapping.Load(key)
	if !ok {
		return v, false
	}

	y, ok := node.(*list.Element).Value.(*cacheEntry[K, V])
	if !ok {
		return v, false
	}

	if time.Now().After(y.expireTime) {
		l.mapping.Delete(key)
		l.list.Remove(node.(*list.Element))
		return v, false
	}

	l.list.MoveToFront(node.(*list.Element))
	return y.data, true
}
