package dns

import (
	"fmt"
	"math"
	"net"
	"net/netip"
	"strings"
	"sync"
	"unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/utils/cache"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lru"
	"golang.org/x/net/dns/dnsmessage"
)

var _ dns.DNS = (*FakeDNS)(nil)

type FakeDNS struct {
	upstream dns.DNS
	*FakeIPPool
}

func NewFakeDNS(upStreamDo dns.DNS, ipRange netip.Prefix, bbolt *cache.Cache) *FakeDNS {
	return &FakeDNS{upStreamDo, NewFakeIPPool(ipRange, bbolt)}
}

func (f *FakeDNS) LookupIP(domain string) ([]net.IP, error) {
	return []net.IP{net.ParseIP(f.FakeIPPool.GetFakeIPForDomain(domain))}, nil
}

func (f *FakeDNS) Record(domain string, t dnsmessage.Type) (dns.IPRecord, error) {
	ipStr := f.FakeIPPool.GetFakeIPForDomain(domain)

	ip := net.ParseIP(ipStr)

	if t == dnsmessage.TypeA && ip.To4() == nil {
		return dns.IPRecord{}, fmt.Errorf("fake ip pool is ipv6, except ipv4")
	}

	if t == dnsmessage.TypeAAAA {
		return dns.IPRecord{IPs: []net.IP{ip.To16()}, TTL: 60}, nil
	}
	return dns.IPRecord{IPs: []net.IP{ip.To4()}, TTL: 60}, nil
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
	r, ok := f.FakeIPPool.GetDomainFromIP(ip.String())
	if !ok {
		return "", fmt.Errorf("not found %s[%s] ptr", ip, name)
	}

	return r, nil
}

func (f *FakeDNS) Do(addr string, b []byte) ([]byte, error) { return f.upstream.Do(addr, b) }

func (f *FakeDNS) Close() error { return nil }

type FakeIPPool struct {
	prefix     netip.Prefix
	current    netip.Addr
	domainToIP *fakeLru

	mu sync.Mutex
}

func NewFakeIPPool(prefix netip.Prefix, bbolt *cache.Cache) *FakeIPPool {
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

func (n *FakeIPPool) GetFakeIPForDomain(s string) string {
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

		if n.domainToIP.ValueExist(addr.String()) {
			continue
		}

		n.domainToIP.Add(s, addr.String())
		return addr.String()
	}
}

func (n *FakeIPPool) GetDomainFromIP(ip string) (string, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.domainToIP.ReverseLoad(ip)
}

func (n *FakeIPPool) LRU() *lru.LRU[string, string] { return n.domainToIP.LRU }

type fakeLru struct {
	LRU   *lru.LRU[string, string]
	bbolt *cache.Cache

	Size uint
}

func newFakeLru(size uint, bbolt *cache.Cache) *fakeLru {
	z := &fakeLru{Size: size, bbolt: bbolt}

	if size > 0 {
		z.LRU = lru.NewLru(uint(size),
			lru.WithOnRemove[string, string](func(s string) {
				bbolt.Delete(unsafe.Slice(unsafe.StringData(s), len(s)))
			}),
		)
	}

	return z
}

func (f *fakeLru) Load(k string) (string, bool) {
	if f.Size <= 0 {
		return "", false
	}

	z, ok := f.LRU.Load(k)
	if ok {
		return z, ok
	}

	if v := f.bbolt.Get(unsafe.Slice(unsafe.StringData(k), len(k))); v != nil {
		vv := string(v)
		f.LRU.Add(k, vv)

		return vv, true
	}

	return "", false
}

func (f *fakeLru) Add(k, v string) {
	if f.Size <= 0 {
		return
	}
	f.LRU.Add(k, v)

	if f.bbolt != nil {
		f.bbolt.Put(unsafe.Slice(unsafe.StringData(k), len(k)), unsafe.Slice(unsafe.StringData(v), len(v)))
		f.bbolt.Put(unsafe.Slice(unsafe.StringData(v), len(v)), unsafe.Slice(unsafe.StringData(k), len(k)))
	}
}

func (f *fakeLru) ValueExist(v string) bool {
	if f.Size <= 0 {
		return false
	}

	exist := f.LRU.ValueExist(v)
	if exist {
		return true
	}

	return f.bbolt.Get(unsafe.Slice(unsafe.StringData(v), len(v))) != nil
}

func (f *fakeLru) ReverseLoad(ip string) (string, bool) {
	if f.Size <= 0 {
		return "", false
	}

	k, ok := f.LRU.ReverseLoad(ip)
	if ok {
		return k, ok
	}

	if kk := f.bbolt.Get(unsafe.Slice(unsafe.StringData(ip), len(ip))); kk != nil {
		k = string(kk)
		f.LRU.Add(k, ip)
		return k, true
	}

	return "", false
}

func (f *fakeLru) LastPopValue() (string, bool) {
	if f.Size <= 0 {
		return "", false
	}
	return f.LRU.LastPopValue()
}
