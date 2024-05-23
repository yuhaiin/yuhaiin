package dns

import (
	"context"
	"fmt"
	"math"
	"net"
	"net/netip"
	"strings"
	"sync"
	"unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/cache"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lru"
	"golang.org/x/net/dns/dnsmessage"
)

var _ netapi.Resolver = (*FakeDNS)(nil)

type FakeDNS struct {
	netapi.Resolver
	ipv4 *FakeIPPool
	ipv6 *FakeIPPool
}

func NewFakeDNS(
	upStreamDo netapi.Resolver,
	ipRange netip.Prefix,
	ipv6Range netip.Prefix,
	bbolt, bboltv6 *cache.Cache,
) *FakeDNS {
	return &FakeDNS{upStreamDo, NewFakeIPPool(ipRange, bbolt), NewFakeIPPool(ipv6Range, bboltv6)}
}

func (f *FakeDNS) Equal(ipRange, ipv6Range netip.Prefix) bool {
	return ipRange.Masked() == f.ipv4.prefix.Masked() && ipv6Range.Masked() == f.ipv6.prefix.Masked()
}

func (f *FakeDNS) Contains(addr netip.Addr) bool {
	return f.ipv4.prefix.Contains(addr) || f.ipv6.prefix.Contains(addr)
}

func (f *FakeDNS) LookupIP(_ context.Context, domain string, opts ...func(*netapi.LookupIPOption)) ([]net.IP, error) {
	opt := &netapi.LookupIPOption{}
	for _, optf := range opts {
		optf(opt)
	}

	if opt.AAAA && !opt.A {
		return []net.IP{f.ipv6.GetFakeIPForDomain(domain).AsSlice()}, nil
	}

	if opt.A && !opt.AAAA {
		return []net.IP{f.ipv4.GetFakeIPForDomain(domain).AsSlice()}, nil
	}

	return []net.IP{f.ipv4.GetFakeIPForDomain(domain).AsSlice(), f.ipv6.GetFakeIPForDomain(domain).AsSlice()}, nil
}

func (f *FakeDNS) Raw(ctx context.Context, req dnsmessage.Question) (dnsmessage.Message, error) {
	if req.Type != dnsmessage.TypeA && req.Type != dnsmessage.TypeAAAA && req.Type != dnsmessage.TypePTR {
		return f.Resolver.Raw(ctx, req)
	}

	newAnswer := func(resource dnsmessage.ResourceBody) dnsmessage.Message {
		msg := dnsmessage.Message{
			Header: dnsmessage.Header{
				ID:                 0,
				Response:           true,
				Authoritative:      false,
				RecursionDesired:   false,
				RCode:              dnsmessage.RCodeSuccess,
				RecursionAvailable: false,
			},
			Questions: []dnsmessage.Question{
				{
					Name:  req.Name,
					Type:  req.Type,
					Class: dnsmessage.ClassINET,
				},
			},
		}

		answer := dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{
				Name:  req.Name,
				Class: dnsmessage.ClassINET,
				TTL:   600,
				Type:  req.Type,
			},
			Body: resource,
		}

		msg.Answers = append(msg.Answers, answer)

		return msg
	}

	if req.Type == dnsmessage.TypePTR {
		domain, err := f.LookupPtr(req.Name.String())
		if err != nil {
			return f.Resolver.Raw(ctx, req)
		}

		msg := newAnswer(&dnsmessage.PTRResource{
			PTR: dnsmessage.MustNewName(domain + "."),
		})

		return msg, nil
	}
	if req.Type == dnsmessage.TypeAAAA {
		ip := f.ipv6.GetFakeIPForDomain(strings.TrimSuffix(req.Name.String(), "."))
		return newAnswer(&dnsmessage.AAAAResource{AAAA: ip.As16()}), nil
	}

	if req.Type == dnsmessage.TypeA {
		ip := f.ipv4.GetFakeIPForDomain(strings.TrimSuffix(req.Name.String(), "."))
		return newAnswer(&dnsmessage.AResource{A: ip.As4()}), nil
	}

	return f.Resolver.Raw(ctx, req)
}

func (f *FakeDNS) GetDomainFromIP(ip netip.Addr) (string, bool) {
	if ip.Unmap().Is6() {
		return f.ipv6.GetDomainFromIP(ip)
	} else {
		return f.ipv4.GetDomainFromIP(ip)
	}
}

var hex = map[byte]byte{
	'0': 0,
	'1': 1,
	'2': 2,
	'3': 3,
	'4': 4,
	'5': 5,
	'6': 6,
	'7': 7,
	'8': 8,
	'9': 9,
	'A': 10,
	'a': 10,
	'b': 11,
	'B': 11,
	'C': 12,
	'c': 12,
	'D': 13,
	'd': 13,
	'e': 14,
	'E': 14,
	'f': 15,
	'F': 15,
}

func RetrieveIPFromPtr(name string) (net.IP, error) {
	i := strings.Index(name, "ip6.arpa.")
	if i != -1 && len(name[:i]) == 64 {
		var ip [16]byte
		for i := range ip {
			ip[i] = hex[name[62-i*4]]*16 + hex[name[62-i*4-2]]
		}
		return net.IP(ip[:]), nil
	}

	if i = strings.Index(name, "in-addr.arpa."); i == -1 {
		return nil, fmt.Errorf("ptr format failed: %s", name)
	}

	var ip [4]byte
	var dotCount uint8

	for _, v := range name[:i] {
		if dotCount > 3 {
			break
		}

		if v == '.' {
			dotCount++
		} else {
			ip[3-dotCount] = ip[3-dotCount]*10 + hex[byte(v)]
		}
	}

	return net.IP(ip[:]), nil
}

func (f *FakeDNS) LookupPtr(name string) (string, error) {
	ip, err := RetrieveIPFromPtr(name)
	if err != nil {
		return "", err
	}

	ipAddr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return "", fmt.Errorf("parse netip.Addr from bytes failed")
	}

	r, ok := f.ipv4.GetDomainFromIP(ipAddr.Unmap())
	if ok {
		return r, nil
	}

	r, ok = f.ipv6.GetDomainFromIP(ipAddr.Unmap())
	if ok {
		return r, nil
	}

	return r, fmt.Errorf("ptr not found")
}

func (f *FakeDNS) Close() error { return nil }

type FakeIPPool struct {
	prefix     netip.Prefix
	current    netip.Addr
	domainToIP *fakeLru

	mu sync.Mutex
}

func NewFakeIPPool(prefix netip.Prefix, bbolt *cache.Cache) *FakeIPPool {
	if bbolt == nil {
		bbolt = cache.NewCache(nil, "")
	}

	prefix = prefix.Masked()

	lenSize := 32
	if prefix.Addr().Is6() {
		lenSize = 128
	}

	var lruSize uint
	if prefix.Bits() == lenSize {
		lruSize = 0
	} else {
		lruSize = uint(math.Pow(2, float64(lenSize-prefix.Bits())) - 1)
	}

	return &FakeIPPool{
		prefix:     prefix,
		current:    prefix.Addr().Prev(),
		domainToIP: newFakeLru(lruSize, bbolt, prefix),
	}
}

func (n *FakeIPPool) GetFakeIPForDomain(s string) netip.Addr {
	if z, ok := n.domainToIP.Load(s); ok {
		return z
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	if z, ok := n.domainToIP.Load(s); ok {
		return z
	}

	if v, ok := n.domainToIP.LastPopValue(); ok {
		n.domainToIP.Add(s, v)
		return v
	}

	for {
		addr := n.current.Next()

		if !n.prefix.Contains(addr) {
			n.current = n.prefix.Addr().Prev()
			continue
		}

		n.current = addr

		if !n.domainToIP.ValueExist(addr) {
			n.domainToIP.Add(s, addr)
			return addr
		}
	}
}

func (n *FakeIPPool) GetDomainFromIP(ip netip.Addr) (string, bool) {
	if !n.prefix.Contains(ip) {
		return "", false
	}

	return n.domainToIP.ReverseLoad(ip.Unmap())
}

func (n *FakeIPPool) LRU() *lru.LRU[string, netip.Addr] { return n.domainToIP.LRU }

type fakeLru struct {
	iprange netip.Prefix
	LRU     *lru.LRU[string, netip.Addr]
	bbolt   *cache.Cache

	Size uint
}

func newFakeLru(size uint, bbolt *cache.Cache, iprange netip.Prefix) *fakeLru {
	z := &fakeLru{Size: size, bbolt: bbolt, iprange: iprange}

	if size > 0 {
		z.LRU = lru.New(
			lru.WithCapacity[string, netip.Addr](size),
			lru.WithOnRemove(func(s string, v netip.Addr) { bbolt.Delete([]byte(s), v.AsSlice()) }),
		)
	}

	return z
}

func (f *fakeLru) Load(host string) (netip.Addr, bool) {
	if f.Size <= 0 {
		return netip.Addr{}, false
	}

	z, ok := f.LRU.Load(host)
	if ok {
		return z, ok
	}

	if ip, ok := netip.AddrFromSlice(f.bbolt.Get(unsafe.Slice(unsafe.StringData(host), len(host)))); ok {
		if f.iprange.Contains(ip) {
			ip = ip.Unmap()
			f.LRU.Add(host, ip)
			return ip, true
		}
	}

	return netip.Addr{}, false
}

func (f *fakeLru) Add(host string, ip netip.Addr) {
	if f.Size <= 0 {
		return
	}
	f.LRU.Add(host, ip)

	if f.bbolt != nil {
		host, ip := []byte(host), ip.AsSlice()
		f.bbolt.Put(host, ip)
		f.bbolt.Put(ip, host)
	}
}

func (f *fakeLru) ValueExist(ip netip.Addr) bool {
	if f.Size <= 0 {
		return false
	}

	if f.LRU.ValueExist(ip) {
		return true
	}

	if host := f.bbolt.Get(ip.AsSlice()); host != nil {
		f.LRU.Add(string(host), ip)
		return true
	}

	return false
}

func (f *fakeLru) ReverseLoad(ip netip.Addr) (string, bool) {
	if f.Size <= 0 {
		return "", false
	}

	host, ok := f.LRU.ReverseLoad(ip)
	if ok {
		return host, ok
	}

	if host = string(f.bbolt.Get(ip.AsSlice())); host != "" {
		if f.iprange.Contains(ip) {
			f.LRU.Add(host, ip)
		}
		return host, true
	}

	return "", false
}

func (f *fakeLru) LastPopValue() (netip.Addr, bool) {
	if f.Size <= 0 {
		return netip.Addr{}, false
	}
	return f.LRU.LastPopValue()
}
