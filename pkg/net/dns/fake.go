package dns

import (
	"fmt"
	"math"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lru"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"golang.org/x/net/dns/dnsmessage"
)

var _ dns.DNS = (*FakeDNS)(nil)

type FakeDNS struct {
	upStreamDo func(b []byte) ([]byte, error)
	pool       *NFakeDNS
}

func WrapFakeDNS(upStreamDo func(b []byte) ([]byte, error), pool *NFakeDNS) *FakeDNS {
	return &FakeDNS{upStreamDo, pool}
}

func (f *FakeDNS) LookupIP(domain string) ([]net.IP, error) {
	return []net.IP{net.ParseIP(f.pool.GetFakeIPForDomain(domain))}, nil
}

func (f *FakeDNS) Record(domain string, t dnsmessage.Type) (dns.IPResponse, error) {
	ipStr := f.pool.GetFakeIPForDomain(domain)

	ip := net.ParseIP(ipStr)

	if t == dnsmessage.TypeA && ip.To4() == nil {
		return nil, fmt.Errorf("fake ip pool is ipv6, except ipv4")
	}

	if t == dnsmessage.TypeAAAA {
		return dns.NewIPResponse([]net.IP{ip.To16()}, 600), nil
	}
	return dns.NewIPResponse([]net.IP{ip.To4()}, 600), nil
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
	r, ok := f.pool.GetDomainFromIP(ip.String())
	if !ok {
		return "", fmt.Errorf("not found %s[%s] ptr", ip, name)
	}

	return r, nil
}

func (f *FakeDNS) Do(b []byte) ([]byte, error) { return f.upStreamDo(b) }

func (f *FakeDNS) Close() error { return nil }

type NFakeDNS struct {
	prefix     netip.Prefix
	current    netip.Addr
	domainToIP *fakeLru

	mu sync.Mutex
}

func NewNFakeDNS(prefix netip.Prefix) *NFakeDNS {
	prefix = prefix.Masked()

	lenSize := 32
	if prefix.Addr().Is6() {
		lenSize = 128
	}

	var lruSize int
	if prefix.Bits() == lenSize {
		lruSize = 0
	} else {
		lruSize = int(math.Pow(2, float64(lenSize-prefix.Bits())) - 1)
	}

	return &NFakeDNS{
		prefix:     prefix,
		current:    prefix.Addr().Prev(),
		domainToIP: newFakeLru(lruSize),
	}
}

func (n *NFakeDNS) GetFakeIPForDomain(s string) string {
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

func (n *NFakeDNS) GetDomainFromIP(ip string) (string, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.domainToIP.ReverseLoad(ip)
}

type fakeLru struct {
	LRU *lru.LRU[string, string]

	size int
}

func newFakeLru(size int) *fakeLru {
	z := &fakeLru{size: size}

	if size > 0 {
		z.LRU = lru.NewLru[string, string](uint(size), time.Duration(0))
	}

	return z
}
func (f *fakeLru) Load(k string) (string, bool) {
	if f.size <= 0 {
		return "", false
	}

	return f.LRU.Load(k)
}

func (f *fakeLru) Add(k, v string) {
	if f.size <= 0 {
		return
	}
	f.LRU.Add(k, v)
}

func (f *fakeLru) ValueExist(v string) bool {
	if f.size <= 0 {
		return false
	}

	return f.LRU.ValueExist(v)
}

func (f *fakeLru) ReverseLoad(ip string) (string, bool) {
	if f.size <= 0 {
		return "", false
	}

	return f.LRU.ReverseLoad(ip)
}

func (f *fakeLru) LastPopValue() (string, bool) {
	if f.size <= 0 {
		return "", false
	}
	return f.LRU.LastPopValue()
}

// old impl

type Fake struct {
	domainToIP *lru.LRU[string, string]
	ipRange    *net.IPNet

	mu sync.Mutex
}

func NewFake(ipRange *net.IPNet) *Fake {
	ones, bits := ipRange.Mask.Size()
	lruSize := int(math.Pow(2, float64(bits-ones)) - 1)
	// if lruSize > 250 {
	// 	lruSize = 250
	// }
	return &Fake{
		ipRange:    ipRange,
		domainToIP: lru.NewLru[string, string](uint(lruSize), 0*time.Minute),
	}
}

// GetFakeIPForDomain checks and generates a fake IP for a domain name
func (fkdns *Fake) GetFakeIPForDomain(domain string) string {
	fkdns.mu.Lock()
	defer fkdns.mu.Unlock()

	if v, ok := fkdns.domainToIP.Load(domain); ok {
		return v
	}
	currentTimeMillis := uint64(time.Now().UnixNano() / 1e6)
	ones, bits := fkdns.ipRange.Mask.Size()
	rooms := bits - ones
	if rooms < 64 {
		currentTimeMillis %= (uint64(1) << rooms)
	}

	bigIntIP := big.NewInt(0).SetBytes(fkdns.ipRange.IP)
	bigIntIP = bigIntIP.Add(bigIntIP, new(big.Int).SetUint64(currentTimeMillis))

	var bytesLen, fillIndex int
	if fkdns.ipRange.IP.To4() == nil { // ipv6
		bytesLen = net.IPv6len
		if len(bigIntIP.Bytes()) != net.IPv6len {
			fillIndex = 1
		}
	} else {
		bytesLen = net.IPv4len
	}

	bytes := pool.GetBytes(bytesLen)
	defer pool.PutBytes(bytes)

	var ip net.IP
	for {
		bigIntIP.FillBytes(bytes[fillIndex:])
		ip = net.IP(bytes)

		// if we run for a long time, we may go back to beginning and start seeing the IP in use
		if ok := fkdns.domainToIP.ValueExist(ip.String()); !ok {
			break
		}

		bigIntIP = bigIntIP.Add(bigIntIP, big.NewInt(1))

		bigIntIP.FillBytes(bytes[fillIndex:])
		if !fkdns.ipRange.Contains(bytes) {
			bigIntIP = big.NewInt(0).SetBytes(fkdns.ipRange.IP)
		}
	}
	fkdns.domainToIP.Add(domain, ip.String())
	return ip.String()
}

func (fkdns *Fake) GetDomainFromIP(ip string) (string, bool) {
	fkdns.mu.Lock()
	defer fkdns.mu.Unlock()
	return fkdns.domainToIP.ReverseLoad(ip)
}
