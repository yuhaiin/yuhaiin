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

	proxy "github.com/Asutorufa/yuhaiin/pkg/net/interfaces"
	"github.com/Asutorufa/yuhaiin/pkg/utils/cache"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lru"
	"golang.org/x/net/dns/dnsmessage"
)

var _ proxy.Resolver = (*FakeDNS)(nil)

type FakeDNS struct {
	proxy.Resolver
	*FakeIPPool
}

func NewFakeDNS(upStreamDo proxy.Resolver, ipRange netip.Prefix, bbolt *cache.Cache) *FakeDNS {
	return &FakeDNS{upStreamDo, NewFakeIPPool(ipRange, bbolt)}
}

func (f *FakeDNS) LookupIP(_ context.Context, domain string) ([]net.IP, error) {
	return []net.IP{f.FakeIPPool.GetFakeIPForDomain(domain).AsSlice()}, nil
}

func (f *FakeDNS) Record(_ context.Context, domain string, t dnsmessage.Type) ([]net.IP, uint32, error) {
	ip := f.FakeIPPool.GetFakeIPForDomain(domain)

	if t == dnsmessage.TypeA && !ip.Is4() {
		return nil, 0, fmt.Errorf("fake ip pool is ipv6, except ipv4")
	}

	return []net.IP{ip.AsSlice()}, 60, nil
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

	r, ok := f.FakeIPPool.GetDomainFromIP(ipAddr.Unmap())
	if !ok {
		return "", fmt.Errorf("not found %s[%s] ptr", ip, name)
	}

	return r, nil
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
		domainToIP: newFakeLru(lruSize, bbolt),
	}
}

func (n *FakeIPPool) GetFakeIPForDomain(s string) netip.Addr {
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
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.domainToIP.ReverseLoad(ip.Unmap())
}

func (n *FakeIPPool) LRU() *lru.LRU[string, netip.Addr] { return n.domainToIP.LRU }

type fakeLru struct {
	LRU   *lru.LRU[string, netip.Addr]
	bbolt *cache.Cache

	Size uint
}

func newFakeLru(size uint, bbolt *cache.Cache) *fakeLru {
	z := &fakeLru{Size: size, bbolt: bbolt}

	if size > 0 {
		z.LRU = lru.NewLru(
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
		ip = ip.Unmap()
		f.LRU.Add(host, ip)
		return ip, true
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
		f.LRU.Add(host, ip)
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
