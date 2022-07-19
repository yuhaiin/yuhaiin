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
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"golang.org/x/net/dns/dnsmessage"
)

var dnsMap syncmap.SyncMap[config.DnsDnsType, func(dns.Config, proxy.Proxy) dns.DNS]

func New(tYPE config.DnsDnsType, config dns.Config, dialer proxy.Proxy) dns.DNS {
	f, ok := dnsMap.Load(tYPE)
	if !ok {
		return dns.NewErrorDNS(fmt.Errorf("no dns type %v process found", tYPE))
	}

	return f(config, dialer)
}

func Register(tYPE config.DnsDnsType, f func(dns.Config, proxy.Proxy) dns.DNS) {
	if f != nil {
		dnsMap.Store(tYPE, f)
	}
}

type client struct {
	subnet []dnsmessage.Resource
	do     func([]byte) ([]byte, error)
	cache  *dnsLruCache[string, cacheElement]

	config dns.Config
}

type cacheElement struct {
	ips         []net.IP
	expireAfter time.Time
}

func NewClient(config dns.Config, send func([]byte) ([]byte, error)) *client {
	c := &client{
		do:     send,
		cache:  newCache[string, cacheElement](200),
		config: config,
	}
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

func (c *client) LookupIP(domain string) (dns.IPResponse, error) {
	if x, ok := c.cache.Load(domain); ok {
		return dns.NewIPResponse(x.ips, uint32(time.Until(x.expireAfter).Seconds())), nil
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
				Name:  dnsmessage.MustNewName(domain + "."),
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			},
		},
		Additionals: c.subnet,
	}

	d, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack dns message failed: %w", err)
	}

	d, err = c.do(d)
	if err != nil {
		return nil, fmt.Errorf("send dns message failed: %w", err)
	}

	var p dnsmessage.Parser
	he, err := p.Start(d)
	if err != nil {
		return nil, err
	}

	if he.ID != req.ID {
		return nil, fmt.Errorf("id not match")
	}

	if he.RCode != dnsmessage.RCodeSuccess {
		return nil, fmt.Errorf("rCode (%v) not success", he.RCode)
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
			return nil, err
		}

		// All Resources in a set should have the same TTL (RFC 2181 Section 5.2).
		ttl = header.TTL

		switch header.Type {
		case dnsmessage.TypeA:
			body, err := p.AResource()
			if err != nil {
				return nil, err
			}
			i = append(i, net.IP(body.A[:]))
		case dnsmessage.TypeAAAA:
			body, err := p.AAAAResource()
			if err != nil {
				return nil, err
			}
			i = append(i, net.IP(body.AAAA[:]))
		default:
			err = p.SkipAnswer()
			if err != nil {
				return nil, err
			}
		}
	}

	if len(i) == 0 {
		return nil, fmt.Errorf("domain %v no dns answer", domain)
	}

	resp := dns.NewIPResponse(i, ttl)

	log.Printf("%s lookup host [%s] success: %v\n", c.config.Name, domain, resp)

	expireAfter := time.Now().Add(time.Duration(ttl) * time.Second)
	c.cache.Add(domain, cacheElement{i, expireAfter}, expireAfter)
	return resp, nil
}

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
