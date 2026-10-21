package fakeip

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/svcb"
	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
)

type pool interface {
	Prefix() netip.Prefix
	GetDomainFromIP(ip netip.Addr) (string, bool)
	GetFakeIPForDomain(s string) netip.Addr
	LeaseDomainFromIP(ip netip.Addr) (string, func(), bool)
}

type closePool interface {
	Close() error
}

var _ netapi.Resolver = (*FakeDNS)(nil)

type FakeDNS struct {
	netapi.Resolver
	ipv4 pool
	ipv6 pool
}

func NewFakeDNS(upStreamDo netapi.Resolver, ipRange netip.Prefix, ipv6Range netip.Prefix, dbPath string) (*FakeDNS, error) {
	ipv4, err := NewSQLiteFakeIPPool(dbPath, ipRange, 655535)
	if err != nil {
		return nil, fmt.Errorf("open sqlite fakeip ipv4 pool failed: %w", err)
	}

	ipv6, err := NewSQLiteFakeIPPool(dbPath, ipv6Range, 655535)
	if err != nil {
		_ = ipv4.Close()
		return nil, fmt.Errorf("open sqlite fakeip ipv6 pool failed: %w", err)
	}

	return &FakeDNS{
		Resolver: upStreamDo,
		ipv4:     ipv4,
		ipv6:     ipv6,
	}, nil
}

func (f *FakeDNS) Close() error {
	var err error
	if closer, ok := f.ipv4.(closePool); ok {
		err = errors.Join(err, closer.Close())
	}
	if closer, ok := f.ipv6.(closePool); ok {
		err = errors.Join(err, closer.Close())
	}
	return err
}

// Ranges returns the prefixes used by the active pools.
func (f *FakeDNS) Ranges() [2]netip.Prefix {
	return [2]netip.Prefix{f.ipv4.Prefix().Masked(), f.ipv6.Prefix().Masked()}
}

func (f *FakeDNS) Equal(ipRange, ipv6Range netip.Prefix) bool {
	return ipRange.Masked() == f.ipv4.Prefix().Masked() && ipv6Range.Masked() == f.ipv6.Prefix().Masked()
}

func (f *FakeDNS) Contains(addr netip.Addr) bool {
	addr = addr.Unmap()
	return f.ipv4.Prefix().Contains(addr) || f.ipv6.Prefix().Contains(addr)
}

func (f *FakeDNS) LookupIP(_ context.Context, domain string, opts ...func(*netapi.LookupIPOption)) (*netapi.IPs, error) {
	if !system.IsDomainName(domain) {
		return nil, &net.DNSError{Name: domain, Err: "no such host", IsNotFound: true}
	}

	opt := &netapi.LookupIPOption{}
	for _, optf := range opts {
		optf(opt)
	}
	result := &netapi.IPs{}
	if opt.Mode != netapi.ResolverModePreferIPv6 {
		ip := f.ipv4.GetFakeIPForDomain(domain)
		if !ip.Is4() {
			return nil, fmt.Errorf("fakeip: cannot allocate IPv4 for %q", domain)
		}
		result.A = []net.IP{ip.AsSlice()}
	}
	if opt.Mode != netapi.ResolverModePreferIPv4 {
		ip := f.ipv6.GetFakeIPForDomain(domain)
		if !ip.Is6() {
			return nil, fmt.Errorf("fakeip: cannot allocate IPv6 for %q", domain)
		}
		result.AAAA = []net.IP{ip.AsSlice()}
	}
	return result, nil
}

func (f *FakeDNS) newAnswerMessage(req netapi.DNSQuestion, code int, resource ...func(dns.Header) dns.RR) *dns.Msg {
	msg := netapi.NewDNSMsg(req)
	msg.RecursionDesired = false
	msg.Rcode = uint16(code)

	if len(resource) == 0 {
		return msg
	}

	for _, resource := range resource {
		msg.Answer = append(msg.Answer, resource(dns.Header{
			Name:  req.Name,
			Class: dns.ClassINET,
			TTL:   40,
		}))
	}

	return msg
}

func (f *FakeDNS) Raw(ctx context.Context, req netapi.DNSQuestion) (*dns.Msg, error) {
	switch req.Qtype {
	case dns.TypeA, dns.TypeAAAA, dns.TypePTR, dns.TypeHTTPS:
	default:
		return f.Resolver.Raw(ctx, req)
	}

	if !system.IsDomainName(req.Name) {
		return f.newAnswerMessage(req, dns.RcodeNameError), nil
	}

	domain := req.Name[:len(req.Name)-1]

	if net.ParseIP(domain) != nil {
		return f.Resolver.Raw(ctx, req)
	}

	switch req.Qtype {
	case dns.TypePTR:
		ip, err := RetrieveIPFromPtr(req.Name)
		if err != nil {
			return f.newAnswerMessage(req, dns.RcodeNameError), nil
		}

		domain, err := f.LookupPtr(ip)
		if err != nil {
			return f.Resolver.Raw(ctx, req)
		}

		msg := f.newAnswerMessage(
			req,
			dns.RcodeSuccess,
			func(header dns.Header) dns.RR {
				return &dns.PTR{
					Hdr: header,
					Ptr: system.AbsDomain(domain),
				}
			},
		)
		return msg, nil

	case dns.TypeHTTPS:
		msg, err := f.Resolver.Raw(ctx, req)
		if err != nil || msg == nil || msg.Rcode != dns.RcodeSuccess {
			return msg, err
		}
		// AliasMode has no SvcParams. Do not synthesize hints unless there
		// is a ServiceMode record to rewrite.
		hasService := false
		for _, rr := range msg.Answer {
			if h, ok := rr.(*dns.HTTPS); ok && h.Priority != 0 {
				hasService = true
				break
			}
		}
		if !hasService {
			return msg, nil
		}
		ipv4 := f.ipv4.GetFakeIPForDomain(domain)
		if !ipv4.Is4() {
			return f.newAnswerMessage(req, dns.RcodeServerFailure), nil
		}
		var ipv6 netip.Addr
		if configuration.IPv6.Load() {
			ipv6 = f.ipv6.GetFakeIPForDomain(domain)
			if !ipv6.Is6() {
				return f.newAnswerMessage(req, dns.RcodeServerFailure), nil
			}
		}
		msg = msg.Copy() // Never mutate a message shared with upstream cache.
		rewriteHTTPSHints(msg, ipv4, ipv6)
		return msg, nil

	case dns.TypeAAAA:
		if !configuration.IPv6.Load() {
			return f.newAnswerMessage(req, dns.RcodeSuccess), nil
		}

		if !netapi.GetContext(ctx).ConnOptions().Resolver().FakeIPSkipCheckUpstream() {
			msg, err := f.Resolver.Raw(ctx, req)
			if err != nil {
				return nil, err
			}

			if !f.existAnswer(msg, dns.TypeAAAA) {
				return msg, nil
			}
		}

		ip := f.ipv6.GetFakeIPForDomain(domain)
		if !ip.Is6() {
			return f.newAnswerMessage(req, dns.RcodeServerFailure), nil
		}

		return f.newAnswerMessage(req, dns.RcodeSuccess, func(header dns.Header) dns.RR {
			return &dns.AAAA{
				Hdr:  header,
				Addr: ip,
			}
		}), nil

	case dns.TypeA:
		if !netapi.GetContext(ctx).ConnOptions().Resolver().FakeIPSkipCheckUpstream() {
			msg, err := f.Resolver.Raw(ctx, req)
			if err != nil {
				return nil, err
			}

			if !f.existAnswer(msg, dns.TypeA) {
				return msg, nil
			}
		}

		ip := f.ipv4.GetFakeIPForDomain(domain)
		if !ip.Is4() {
			return f.newAnswerMessage(req, dns.RcodeServerFailure), nil
		}

		return f.newAnswerMessage(req, dns.RcodeSuccess, func(header dns.Header) dns.RR {
			return &dns.A{
				Hdr:  header,
				Addr: ip,
			}
		}), nil
	}

	return f.Resolver.Raw(ctx, req)
}

func (f *FakeDNS) existAnswer(msg *dns.Msg, t uint16) bool {
	for _, answer := range msg.Answer {
		if dns.RRToType(answer) == t {
			return true
		}
	}
	return false
}

// LeaseDomainFromIP prevents pool eviction while a recovered destination is in use.
func (f *FakeDNS) LeaseDomainFromIP(ip netip.Addr) (string, func(), bool) {
	ip = ip.Unmap()
	if ip.Is6() {
		return f.ipv6.LeaseDomainFromIP(ip)
	}
	return f.ipv4.LeaseDomainFromIP(ip)
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

// rewriteHTTPSHints changes only ServiceMode records. Never insert parameters
// into AliasMode (SvcPriority 0), never duplicate hint keys, and never mutate a
// response shared with the upstream DNS cache. Preserve unrelated SvcParams
// such as ALPN, ECH, port and mandatory. A changed RRset cannot retain its
// upstream DNSSEC signatures or an authenticated-data assertion.
func rewriteHTTPSHints(msg *dns.Msg, ipv4, ipv6 netip.Addr) {
	answer := make([]dns.RR, 0, len(msg.Answer))
	changed := false
	for _, rr := range msg.Answer {
		https, ok := rr.(*dns.HTTPS)
		if !ok || https.Priority == 0 {
			answer = append(answer, rr)
			continue
		}
		copyRR := *https
		copyRR.Value = make([]svcb.Pair, 0, len(https.Value)+2)
		for _, value := range https.Value {
			key := svcb.PairToKey(value)
			if key != svcb.KeyIPv4Hint && key != svcb.KeyIPv6Hint {
				copyRR.Value = append(copyRR.Value, value)
			}
		}
		if ipv4.Is4() {
			copyRR.Value = append(copyRR.Value, &svcb.IPV4HINT{Hint: []netip.Addr{ipv4}})
		}
		if ipv6.Is6() {
			copyRR.Value = append(copyRR.Value, &svcb.IPV6HINT{Hint: []netip.Addr{ipv6}})
		}
		sort.Slice(copyRR.Value, func(i, j int) bool {
			return svcb.PairToKey(copyRR.Value[i]) < svcb.PairToKey(copyRR.Value[j])
		})
		answer = append(answer, &copyRR)
		changed = true
	}
	if !changed {
		return
	}
	msg.AuthenticatedData = false
	msg.Answer = discardHTTPSSignatures(answer)
	msg.Ns = discardHTTPSSignatures(msg.Ns)
	msg.Extra = discardHTTPSSignatures(msg.Extra)
}

func discardHTTPSSignatures(rrs []dns.RR) []dns.RR {
	var filtered []dns.RR
	for _, rr := range rrs {
		if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeHTTPS {
			if filtered == nil {
				filtered = make([]dns.RR, 0, len(rrs))
				// Keep entries preceding the first removed signature.
				for _, prev := range rrs {
					if prev == rr {
						break
					}
					filtered = append(filtered, prev)
				}
			}
			continue
		}
		if filtered != nil {
			filtered = append(filtered, rr)
		}
	}
	if filtered != nil {
		return filtered
	}
	return rrs
}
