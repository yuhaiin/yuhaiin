package resolver

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/cache"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lru"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
	"golang.org/x/net/dns/dnsmessage"
)

var _ netapi.Resolver = (*FakeDNS)(nil)

type FakeDNS struct {
	netapi.Resolver
	ipv4 *FakeIPPool
	ipv6 *FakeIPPool
}

func NewFakeDNS(upStreamDo netapi.Resolver, ipRange netip.Prefix, ipv6Range netip.Prefix, db cache.RecursionCache) *FakeDNS {
	return &FakeDNS{
		upStreamDo,
		NewFakeIPPool(ipRange, db),
		NewFakeIPPool(ipv6Range, db),
	}
}

func (f *FakeDNS) Flush() {
	f.ipv4.Flush()
	f.ipv6.Flush()
}

func (f *FakeDNS) Equal(ipRange, ipv6Range netip.Prefix) bool {
	return ipRange.Masked() == f.ipv4.prefix.Masked() && ipv6Range.Masked() == f.ipv6.prefix.Masked()
}

func (f *FakeDNS) Contains(addr netip.Addr) bool {
	addr = addr.Unmap()
	return f.ipv4.prefix.Contains(addr) || f.ipv6.prefix.Contains(addr)
}

func (f *FakeDNS) LookupIP(_ context.Context, domain string, opts ...func(*netapi.LookupIPOption)) (*netapi.IPs, error) {
	if !system.IsDomainName(domain) {
		return nil, &net.DNSError{
			Name:       domain,
			Err:        "no such host",
			IsNotFound: true,
		}
	}

	opt := &netapi.LookupIPOption{}
	for _, optf := range opts {
		optf(opt)
	}

	switch opt.Mode {
	case netapi.ResolverModePreferIPv4:
		return &netapi.IPs{A: []net.IP{f.ipv4.GetFakeIPForDomain(domain).AsSlice()}}, nil
	case netapi.ResolverModePreferIPv6:
		return &netapi.IPs{AAAA: []net.IP{f.ipv6.GetFakeIPForDomain(domain).AsSlice()}}, nil
	}

	return &netapi.IPs{
		A:    []net.IP{f.ipv4.GetFakeIPForDomain(domain).AsSlice()},
		AAAA: []net.IP{f.ipv6.GetFakeIPForDomain(domain).AsSlice()},
	}, nil
}

func (f *FakeDNS) newAnswerMessage(req dnsmessage.Question, code dnsmessage.RCode, resource dnsmessage.ResourceBody) dnsmessage.Message {
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 0,
			Response:           true,
			Authoritative:      false,
			RecursionDesired:   false,
			RCode:              code,
			RecursionAvailable: true,
		},
		Questions: []dnsmessage.Question{
			{
				Name:  req.Name,
				Type:  req.Type,
				Class: dnsmessage.ClassINET,
			},
		},
	}

	if resource == nil {
		return msg
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

func (f *FakeDNS) Raw(ctx context.Context, req dnsmessage.Question) (dnsmessage.Message, error) {
	switch req.Type {
	case dnsmessage.TypeA, dnsmessage.TypeAAAA, dnsmessage.TypePTR, TypeHTTPS:
	default:
		return f.Resolver.Raw(ctx, req)
	}

	if !system.IsDomainName(req.Name.String()) {
		return f.newAnswerMessage(req, dnsmessage.RCodeNameError, nil), nil
	}

	domain := unsafe.String(unsafe.SliceData(req.Name.Data[0:req.Name.Length-1]), req.Name.Length-1)

	if net.ParseIP(domain) != nil {
		return f.Resolver.Raw(ctx, req)
	}

	switch req.Type {
	case dnsmessage.TypePTR:
		domain, err := f.LookupPtr(req.Name.String())
		if err != nil {
			return f.Resolver.Raw(ctx, req)
		}

		msg := f.newAnswerMessage(
			req,
			dnsmessage.RCodeSuccess,
			&dnsmessage.PTRResource{
				PTR: dnsmessage.MustNewName(system.AbsDomain(domain)),
			},
		)
		return msg, nil

	case TypeHTTPS:
		// wait https://github.com/golang/go/issues/43790 implement
		msg, err := f.Resolver.Raw(ctx, req)
		if err != nil {
			return msg, err
		}

		ipv6 := f.ipv6.GetFakeIPForDomain(domain)
		ipv4 := f.ipv4.GetFakeIPForDomain(domain)

		appendIPHint(msg, []netip.Addr{ipv4}, []netip.Addr{ipv6})
		return msg, nil

	case dnsmessage.TypeAAAA:
		if !configuration.IPv6.Load() {
			return f.newAnswerMessage(req, dnsmessage.RCodeSuccess, nil), nil
		}

		ip := f.ipv6.GetFakeIPForDomain(domain)
		return f.newAnswerMessage(req, dnsmessage.RCodeSuccess, &dnsmessage.AAAAResource{AAAA: ip.As16()}), nil

	case dnsmessage.TypeA:
		ip := f.ipv4.GetFakeIPForDomain(domain)
		return f.newAnswerMessage(req, dnsmessage.RCodeSuccess, &dnsmessage.AResource{A: ip.As4()}), nil
	}

	return f.Resolver.Raw(ctx, req)
}

func (f *FakeDNS) GetDomainFromIP(ip netip.Addr) (string, bool) {
	ip = ip.Unmap()
	if ip.Is6() {
		return f.ipv6.GetDomainFromIP(ip)
	} else {
		return f.ipv4.GetDomainFromIP(ip)
	}
}

// fromHexByte converts a single hexadecimal ASCII digit character into an
// integer from 0 to 15.  For all other characters it returns 0xff.
//
// TODO(e.burkov):  This should be covered with tests after adding HasSuffixFold
// into stringutil.
func fromHexByte(c byte) (n byte) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	default:
		return 0xff
	}
}

// ARPA reverse address domains.
const (
	arpaV4Suffix = ".in-addr.arpa."
	arpaV6Suffix = ".ip6.arpa."

	arpaV4MaxIPLen = len("000.000.000.000")
	arpaV6MaxIPLen = len("0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0")

	arpaV4SuffixLen = len(arpaV4Suffix)
	arpaV6SuffixLen = len(arpaV6Suffix)
)

func RetrieveIPFromPtr(name string) (net.IP, error) {
	if strings.HasSuffix(name, arpaV6Suffix) && len(name)-arpaV6SuffixLen == arpaV6MaxIPLen {
		var ip [16]byte
		for i := range ip {
			ip[i] = fromHexByte(name[62-i*4])*16 + fromHexByte(name[62-i*4-2])
		}
		return ip[:], nil
	}

	if !strings.HasSuffix(name, arpaV4Suffix) {
		return nil, fmt.Errorf("retrieve ip from ptr failed: %s", name)
	}

	reverseIPv4, err := netip.ParseAddr(name[:len(name)-arpaV4SuffixLen])
	if err != nil || !reverseIPv4.Is4() {
		return nil, fmt.Errorf("retrieve ip from ptr failed: %s, %w", name, err)
	}

	ipv4 := reverseIPv4.As4()
	slices.Reverse(ipv4[:])
	return ipv4[:], nil
}

func (f *FakeDNS) LookupPtr(name string) (string, error) {
	ip, err := RetrieveIPFromPtr(name)
	if err != nil {
		return "", err
	}

	ipAddr, _ := netip.AddrFromSlice(ip)
	ipAddr = ipAddr.Unmap()

	var r string
	var ok bool
	if ipAddr.Is6() {
		r, ok = f.ipv6.GetDomainFromIP(ipAddr)
	} else {
		r, ok = f.ipv4.GetDomainFromIP(ipAddr)
	}
	if ok {
		return r, nil
	}

	return r, fmt.Errorf("ptr not found")
}

func (f *FakeDNS) Close() error { return nil }

type FakeIPPool struct {
	current    netip.Addr
	domainToIP *fakeLru

	prefix netip.Prefix

	mu sync.Mutex
}

func NewFakeIPPool(prefix netip.Prefix, db cache.RecursionCache) *FakeIPPool {
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
		domainToIP: newFakeLru(lruSize, db, prefix),
	}
}

func (n *FakeIPPool) Flush() {
	n.domainToIP.Flush()
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

	looped := false

	for {
		addr := n.current.Next()

		if !n.prefix.Contains(addr) {
			n.current = n.prefix.Addr().Prev()

			if looped {
				addr := n.current.Next()
				n.current = addr
				n.domainToIP.Add(s, addr)
				return addr
			}

			looped = true
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

type fakeLru struct {
	bbolt cache.Cache

	LRU     *lru.ReverseSyncLru[string, netip.Addr]
	iprange netip.Prefix

	Size uint
}

func newFakeLru(size uint, db cache.RecursionCache, iprange netip.Prefix) *fakeLru {
	var bboltCache cache.RecursionCache
	if iprange.Addr().Unmap().Is6() {
		bboltCache = db.NewCache("fakedns_cachev6")
	} else {

		bboltCache = db.NewCache("fakedns_cache")
	}

	z := &fakeLru{Size: size, bbolt: bboltCache, iprange: iprange}

	if size <= 0 {
		return z
	}

	z.LRU = lru.NewSyncReverseLru(
		lru.WithLruOptions(
			lru.WithCapacity[string, netip.Addr](size),
			lru.WithOnRemove(func(s string, v netip.Addr) {
				_ = bboltCache.Delete([]byte(s), v.AsSlice())
			}),
		),
		lru.WithOnValueChanged[string](func(old, new netip.Addr) {
			_ = bboltCache.Delete(old.AsSlice())
		}),
	)

	err := bboltCache.Range(func(k, v []byte) bool {
		ip, ok := netip.AddrFromSlice(k)
		if !ok {
			return true
		}

		if iprange.Contains(ip) {
			z.LRU.Add(string(v), ip)
		}

		return true
	})
	if err != nil && !errors.Is(err, cache.ErrBucketNotExist) {
		log.Error("fakeip range cache failed", "err", err)
	}

	log.Info("fakeip lru init", "get cache", z.LRU.Len(), "isIpv6", iprange.Addr().Unmap().Is6(), "capacity", size)

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

	return netip.Addr{}, false
}

func (f *fakeLru) Add(host string, ip netip.Addr) {
	if f.Size <= 0 {
		return
	}
	f.LRU.Add(host, ip)

	if f.bbolt != nil {
		host, ip := []byte(host), ip.AsSlice()
		_ = f.bbolt.Put(host, ip)
		_ = f.bbolt.Put(ip, host)
	}
}

func (f *fakeLru) ValueExist(ip netip.Addr) bool {
	if f.Size <= 0 {
		return false
	}

	if f.LRU.ValueExist(ip) {
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

	v, _ := f.bbolt.Get(ip.AsSlice())
	if host = string(v); host != "" {
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

func (f *fakeLru) Flush() {
	// no sync cache
	// flush data to disk before close
	f.bbolt.Close()
}
