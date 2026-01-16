package fakeip

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/cache"
	"github.com/Asutorufa/yuhaiin/pkg/cache/pebble"
	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
	"github.com/miekg/dns"
)

type pool interface {
	Prefix() netip.Prefix
	GetDomainFromIP(ip netip.Addr) (string, bool)
	GetFakeIPForDomain(s string) netip.Addr
}

var _ netapi.Resolver = (*FakeDNS)(nil)

type FakeDNS struct {
	netapi.Resolver
	ipv4 pool
	ipv6 pool
}

func NewFakeDNS(upStreamDo netapi.Resolver, ipRange netip.Prefix, ipv6Range netip.Prefix, db cache.Cache) *FakeDNS {
	f := &FakeDNS{
		Resolver: upStreamDo,
	}

	if v, ok := db.(*pebble.Cache); ok {
		log.Info("fakeip use full pebble disk cache")
		f.ipv4 = NewDiskFakeIPPool(ipRange, v, 655535)
		f.ipv6 = NewDiskFakeIPPool(ipv6Range, v, 655535)
	} else {
		f.ipv4 = NewFakeIPPool(ipRange, db)
		f.ipv6 = NewFakeIPPool(ipv6Range, db)
	}

	return f
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

func (f *FakeDNS) newAnswerMessage(req dns.Question, code int, resource ...func(hedaer dns.RR_Header) dns.RR) dns.Msg {
	msg := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                 0,
			Response:           true,
			Authoritative:      false,
			RecursionDesired:   false,
			Rcode:              code,
			RecursionAvailable: true,
		},
		Question: []dns.Question{
			{
				Name:   req.Name,
				Qtype:  req.Qtype,
				Qclass: dns.ClassINET,
			},
		},
	}

	if len(resource) == 0 {
		return msg
	}

	for _, resource := range resource {
		msg.Answer = append(msg.Answer, resource(dns.RR_Header{
			Name:   req.Name,
			Rrtype: req.Qtype,
			Class:  dns.ClassINET,
			Ttl:    40,
		}))
	}

	return msg
}

func (f *FakeDNS) Raw(ctx context.Context, req dns.Question) (dns.Msg, error) {
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
			func(header dns.RR_Header) dns.RR {
				return &dns.PTR{
					Hdr: header,
					Ptr: system.AbsDomain(domain),
				}
			},
		)
		return msg, nil

	case dns.TypeHTTPS:
		msg, err := f.Resolver.Raw(ctx, req)
		if err != nil {
			return msg, err
		}

		ipv6 := f.ipv6.GetFakeIPForDomain(domain)
		ipv4 := f.ipv4.GetFakeIPForDomain(domain)

		appendIPHint(msg, []net.IP{ipv4.AsSlice()}, []net.IP{ipv6.AsSlice()})

		return msg, nil

	case dns.TypeAAAA:
		if !configuration.IPv6.Load() {
			return f.newAnswerMessage(req, dns.RcodeSuccess), nil
		}

		if !netapi.GetContext(ctx).ConnOptions().Resolver().FakeIPSkipCheckUpstream() {
			msg, err := f.Resolver.Raw(ctx, req)
			if err != nil {
				return dns.Msg{}, err
			}

			if !f.existAnswer(msg, dns.Type(dns.TypeAAAA)) {
				return msg, nil
			}
		}

		ip := f.ipv6.GetFakeIPForDomain(domain)

		return f.newAnswerMessage(req, dns.RcodeSuccess, func(header dns.RR_Header) dns.RR {
			return &dns.AAAA{
				Hdr:  header,
				AAAA: ip.AsSlice(),
			}
		}), nil

	case dns.TypeA:
		if !netapi.GetContext(ctx).ConnOptions().Resolver().FakeIPSkipCheckUpstream() {
			msg, err := f.Resolver.Raw(ctx, req)
			if err != nil {
				return dns.Msg{}, err
			}

			if !f.existAnswer(msg, dns.Type(dns.TypeA)) {
				return msg, nil
			}
		}

		ip := f.ipv4.GetFakeIPForDomain(domain)

		return f.newAnswerMessage(req, dns.RcodeSuccess, func(header dns.RR_Header) dns.RR {
			return &dns.A{
				Hdr: header,
				A:   ip.AsSlice(),
			}
		}), nil
	}

	return f.Resolver.Raw(ctx, req)
}

func (f *FakeDNS) existAnswer(msg dns.Msg, t dns.Type) bool {
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

func appendIPHint(msg dns.Msg, ipv4, ipv6 []net.IP) {
	if len(ipv4) == 0 && len(ipv6) == 0 {
		return
	}

	for _, v := range msg.Answer {
		if v.Header().Rrtype != dns.TypeHTTPS {
			continue
		}

		https, ok := v.(*dns.HTTPS)
		if !ok {
			continue
		}

		// the raw message already cloned, so we no need copy anymore here
		if len(ipv4) > 0 {
			https.Value = append(https.Value, &dns.SVCBIPv4Hint{
				Hint: ipv4,
			})
		}

		if len(ipv6) > 0 {
			https.Value = append(https.Value, &dns.SVCBIPv6Hint{
				Hint: ipv6,
			})
		}

		break
	}
}
