package dns

import (
	"bytes"
	"container/list"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type client struct {
	template dnsmessage.Message
	do       func([]byte) ([]byte, error)
	cache    *dnsLruCache[string, []net.IP]
}

func NewClient(subnet *net.IPNet, send func([]byte) ([]byte, error)) *client {
	c := &client{
		do:    send,
		cache: newCache[string, []net.IP](200),
		template: dnsmessage.Message{
			Header: dnsmessage.Header{
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
					Name:  dnsmessage.MustNewName("."),
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
				},
			},
		},
	}
	if subnet != nil {
		optionData := bytes.NewBuffer(nil)
		mask, _ := subnet.Mask.Size()
		ip := subnet.IP.To4()
		if ip == nil { // family https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml
			optionData.Write([]byte{0b00000000, 0b00000010}) // family ipv6 2
			ip = subnet.IP.To16()
		} else {
			optionData.Write([]byte{0b00000000, 0b00000001}) // family ipv4 1
		}
		optionData.WriteByte(byte(mask)) // mask
		optionData.WriteByte(0b00000000) // 0 In queries, it MUST be set to 0.
		optionData.Write(ip)             // subnet IP

		c.template.Additionals = append(c.template.Additionals, dnsmessage.Resource{
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
		})
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
	if x, _ := c.cache.Load(domain); x != nil {
		return x, nil
	}
	req := c.template
	req.ID = uint16(rand.Intn(65535))
	req.Questions[0].Name = dnsmessage.MustNewName(domain + ".")
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

	p.SkipAllQuestions()

	var ttl uint32
	i := make([]net.IP, 0, 1)
	for {
		header, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			if len(i) == 0 {
				return nil, fmt.Errorf("no answer")
			}
			c.cache.Add(domain, i, time.Now().Add(time.Duration(ttl)*time.Second))
			return i, nil
		}
		if err != nil {
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
