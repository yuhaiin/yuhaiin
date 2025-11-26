package resolver

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/cache"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lru"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
	dnsmessage "github.com/miekg/dns"
)

var _ netapi.Resolver = (*FakeDNS)(nil)

type FakeDNS struct {
	netapi.Resolver
	ipv4 *FakeIPPool
	ipv6 *FakeIPPool
}

func NewFakeDNS(upStreamDo netapi.Resolver, ipRange netip.Prefix, ipv6Range netip.Prefix, db cache.Cache) *FakeDNS {
	return &FakeDNS{
		upStreamDo,
		NewFakeIPPool(ipRange, db),
		NewFakeIPPool(ipv6Range, db),
	}
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

func (f *FakeDNS) newAnswerMessage(req dnsmessage.Question, code int, resource ...func(hedaer dnsmessage.RR_Header) dnsmessage.RR) dnsmessage.Msg {
	msg := dnsmessage.Msg{
		MsgHdr: dnsmessage.MsgHdr{
			Id:                 0,
			Response:           true,
			Authoritative:      false,
			RecursionDesired:   false,
			Rcode:              code,
			RecursionAvailable: true,
		},
		Question: []dnsmessage.Question{
			{
				Name:   req.Name,
				Qtype:  req.Qtype,
				Qclass: dnsmessage.ClassINET,
			},
		},
	}

	if len(resource) == 0 {
		return msg
	}

	for _, resource := range resource {
		msg.Answer = append(msg.Answer, resource(dnsmessage.RR_Header{
			Name:   req.Name,
			Rrtype: req.Qtype,
			Class:  dnsmessage.ClassINET,
			Ttl:    40,
		}))
	}

	return msg
}

func (f *FakeDNS) Raw(ctx context.Context, req dnsmessage.Question) (dnsmessage.Msg, error) {
	switch req.Qtype {
	case dnsmessage.TypeA, dnsmessage.TypeAAAA, dnsmessage.TypePTR, dnsmessage.TypeHTTPS:
	default:
		return f.Resolver.Raw(ctx, req)
	}

	if !system.IsDomainName(req.Name) {
		return f.newAnswerMessage(req, dnsmessage.RcodeNameError), nil
	}

	domain := req.Name[:len(req.Name)-1]

	if net.ParseIP(domain) != nil {
		return f.Resolver.Raw(ctx, req)
	}

	switch req.Qtype {
	case dnsmessage.TypePTR:
		ip, err := RetrieveIPFromPtr(req.Name)
		if err != nil {
			return f.newAnswerMessage(req, dnsmessage.RcodeNameError), nil
		}

		domain, err := f.LookupPtr(ip)
		if err != nil {
			return f.Resolver.Raw(ctx, req)
		}

		msg := f.newAnswerMessage(
			req,
			dnsmessage.RcodeSuccess,
			func(header dnsmessage.RR_Header) dnsmessage.RR {
				return &dnsmessage.PTR{
					Hdr: header,
					Ptr: system.AbsDomain(domain),
				}
			},
		)
		return msg, nil

	case dnsmessage.TypeHTTPS:
		msg, err := f.Resolver.Raw(ctx, req)
		if err != nil {
			return msg, err
		}

		ipv6 := f.ipv6.GetFakeIPForDomain(domain)
		ipv4 := f.ipv4.GetFakeIPForDomain(domain)

		appendIPHint(msg, []net.IP{ipv4.AsSlice()}, []net.IP{ipv6.AsSlice()})

		return msg, nil

	case dnsmessage.TypeAAAA:
		if !configuration.IPv6.Load() {
			return f.newAnswerMessage(req, dnsmessage.RcodeSuccess), nil
		}

		if !netapi.GetContext(ctx).ConnOptions().Resolver().FakeIPSkipCheckUpstream() {
			msg, err := f.Resolver.Raw(ctx, req)
			if err != nil {
				return dnsmessage.Msg{}, err
			}

			if !f.existAnswer(msg, dnsmessage.Type(dnsmessage.TypeAAAA)) {
				return msg, nil
			}
		}

		ip := f.ipv6.GetFakeIPForDomain(domain)

		return f.newAnswerMessage(req, dnsmessage.RcodeSuccess, func(header dnsmessage.RR_Header) dnsmessage.RR {
			return &dnsmessage.AAAA{
				Hdr:  header,
				AAAA: ip.AsSlice(),
			}
		}), nil

	case dnsmessage.TypeA:
		if !netapi.GetContext(ctx).ConnOptions().Resolver().FakeIPSkipCheckUpstream() {
			msg, err := f.Resolver.Raw(ctx, req)
			if err != nil {
				return dnsmessage.Msg{}, err
			}

			if !f.existAnswer(msg, dnsmessage.Type(dnsmessage.TypeA)) {
				return msg, nil
			}
		}

		ip := f.ipv4.GetFakeIPForDomain(domain)

		return f.newAnswerMessage(req, dnsmessage.RcodeSuccess, func(header dnsmessage.RR_Header) dnsmessage.RR {
			return &dnsmessage.A{
				Hdr: header,
				A:   ip.AsSlice(),
			}
		}), nil
	}

	return f.Resolver.Raw(ctx, req)
}

func (f *FakeDNS) existAnswer(msg dnsmessage.Msg, t dnsmessage.Type) bool {
	for _, answer := range msg.Answer {
		if answer.Header().Rrtype == uint16(t) {
			return true
		}
	}
	return false
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

	v4name := name[:len(name)-arpaV4SuffixLen]

	ipv4 := make([]byte, 0, 4)
	for v := range strings.SplitSeq(v4name, ".") {
		if len(ipv4) == 4 {
			return nil, fmt.Errorf("invalid ipv4 ptr: %s", name)
		}

		z, err := strconv.ParseUint(v, 10, 8)
		if err != nil {
			return nil, fmt.Errorf("parse to ip failed: %w, name: %s", err, name)
		}
		ipv4 = append(ipv4, byte(z))
	}

	if len(ipv4) != 4 {
		return nil, fmt.Errorf("invalid ipv4 ptr: %s", name)
	}

	ipv4[0], ipv4[1], ipv4[2], ipv4[3] = ipv4[3], ipv4[2], ipv4[1], ipv4[0]

	return ipv4, nil
}

func (f *FakeDNS) LookupPtr(ip net.IP) (string, error) {
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

func NewFakeIPPool(prefix netip.Prefix, db cache.Cache) *FakeIPPool {
	prefix = prefix.Masked()

	lenSize := 32
	if prefix.Addr().Is6() {
		lenSize = 128
	}

	var lruSize int
	if prefix.Bits() == lenSize {
		lruSize = 0
	} else {
		size := math.Pow(2, float64(lenSize-prefix.Bits())) - 1
		if size > 65535 {
			lruSize = 65535
		} else {
			lruSize = int(size)
		}
	}

	return &FakeIPPool{
		prefix:     prefix,
		current:    prefix.Addr().Prev(),
		domainToIP: newFakeLru(lruSize, db, prefix),
	}
}

func (n *FakeIPPool) GetFakeIPForDomain(s string) netip.Addr {
	if z, ok := n.domainToIP.Load(s); ok {
		metrics.Counter.AddFakeIPCacheHit()
		return z
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	if z, ok := n.domainToIP.Load(s); ok {
		metrics.Counter.AddFakeIPCacheHit()
		return z
	}

	metrics.Counter.AddFakeIPCacheMiss()

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

	return n.domainToIP.ReverseLoad(ip)
}

type fakeLru struct {
	bbolt cache.Cache

	LRU     *lru.ReverseSyncLru[string, netip.Addr]
	iprange netip.Prefix

	Size int
}

func newFakeLru(size int, db cache.Cache, iprange netip.Prefix) *fakeLru {
	var bboltCache cache.Cache
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
			lru.WithCapacity[string, netip.Addr](int(size)),
			lru.WithOnRemove(func(s string, v netip.Addr) {
				_ = bboltCache.Delete(slices.Values([][]byte{[]byte(s), v.AsSlice()}))
			}),
		),
		lru.WithOnValueChanged[string](func(old, new netip.Addr) {
			_ = bboltCache.Delete(slices.Values([][]byte{old.AsSlice()}))
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
		_ = f.bbolt.Put(func(yield func([]byte, []byte) bool) {
			if !yield(host, ip) {
				return
			}
			_ = yield(ip, host)
		})
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
