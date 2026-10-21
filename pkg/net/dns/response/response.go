// Package response provides custom DNS answers independently of upstream
// selection, hosts mappings and synthetic address allocation.
package response

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"

	"codeberg.org/miekg/dns"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type rule struct {
	index   int
	rcode   uint16
	records []dns.RR
}

type snapshot struct {
	exact    map[string]map[uint16]*rule
	wildcard map[string]map[uint16]*rule
}

// Resolver owns immutable rule snapshots. Close does not close the borrowed
// upstream; the application owns each resolver's lifetime separately.
type Resolver struct {
	upstream netapi.Resolver
	current  atomic.Pointer[snapshot]
}

func New(upstream netapi.Resolver) *Resolver { return &Resolver{upstream: upstream} }

func (r *Resolver) Apply(config contract.ResponseRules) error {
	next := &snapshot{exact: make(map[string]map[uint16]*rule), wildcard: make(map[string]map[uint16]*rule)}
	for i, entry := range config.Rules {
		records, err := entry.Records()
		if err != nil {
			return fmt.Errorf("rule %d: %w", i+1, err)
		}
		name := strings.ToLower(strings.TrimSuffix(entry.Domain, "."))
		index := next.exact
		if suffix, ok := strings.CutPrefix(name, "*."); ok {
			name, index = suffix, next.wildcard
		} else if name == "*" {
			name, index = "", next.wildcard
		}
		if index[name] == nil {
			index[name] = make(map[uint16]*rule)
		}
		typ := dns.StringToType[entry.QueryType] // zero is the explicit '*' selector.
		if index[name][typ] == nil {
			index[name][typ] = &rule{index: i, rcode: dns.StringToRcode[entry.Rcode], records: records}
		}
	}
	r.current.Store(next)
	return nil
}

func (s *snapshot) match(req netapi.DNSQuestion) *rule {
	if s == nil || req.Qclass != dns.ClassINET {
		return nil
	}
	name := strings.ToLower(strings.TrimSuffix(req.Name, "."))
	var best *rule
	consider := func(entries map[uint16]*rule) {
		for _, typ := range [...]uint16{req.Qtype, 0} {
			if candidate := entries[typ]; candidate != nil && (best == nil || candidate.index < best.index) {
				best = candidate
			}
		}
	}
	consider(s.exact[name])
	for {
		_, suffix, ok := strings.Cut(name, ".")
		if !ok {
			break
		}
		consider(s.wildcard[suffix])
		name = suffix
	}
	consider(s.wildcard[""])
	return best
}

func answer(req netapi.DNSQuestion, entry *rule) *dns.Msg {
	msg := netapi.NewDNSMsg(req)
	msg.Rcode = entry.rcode
	msg.Answer = make([]dns.RR, len(entry.records))
	for i, rr := range entry.records {
		if https, ok := rr.(*dns.HTTPS); ok {
			// HTTPS inherits SVCB.Clone, whose return type is SVCB.
			rr = &dns.HTTPS{SVCB: *https.SVCB.Clone().(*dns.SVCB)}
		} else {
			rr = rr.Clone()
		}
		rr.Header().Name = req.Name
		msg.Answer[i] = rr
	}
	return msg
}

func (r *Resolver) LocalResponse(req netapi.DNSQuestion) (*dns.Msg, bool) {
	if entry := r.current.Load().match(req); entry != nil {
		return answer(req, entry), true
	}
	return nil, false
}

func (r *Resolver) Raw(ctx context.Context, req netapi.DNSQuestion) (*dns.Msg, error) {
	if msg, ok := r.LocalResponse(req); ok {
		return msg, nil
	}
	return r.upstream.Raw(ctx, req)
}

func (r *Resolver) LookupIP(ctx context.Context, name string, opts ...func(*netapi.LookupIPOption)) (*netapi.IPs, error) {
	opt := &netapi.LookupIPOption{}
	for _, apply := range opts {
		apply(opt)
	}
	s := r.current.Load()
	query := netapi.DNSQuestion{Name: strings.TrimSuffix(name, ".") + ".", Qclass: dns.ClassINET}
	query.Qtype = dns.TypeA
	a := s.match(query)
	query.Qtype = dns.TypeAAAA
	aaaa := s.match(query)
	if a == nil && aaaa == nil {
		return r.upstream.LookupIP(ctx, name, opts...)
	}
	lookup := func(typ uint16, entry *rule, mode netapi.ResolverMode) ([]net.IP, error) {
		if entry == nil {
			ips, err := r.upstream.LookupIP(ctx, name, func(o *netapi.LookupIPOption) { o.Mode = mode })
			if err != nil {
				return nil, err
			}
			if typ == dns.TypeA {
				return ips.A, nil
			}
			return ips.AAAA, nil
		}
		if entry.rcode != dns.RcodeSuccess {
			return nil, &net.DNSError{Name: name, Err: dns.RcodeToString[entry.rcode], IsNotFound: entry.rcode == dns.RcodeNameError, IsTemporary: entry.rcode == dns.RcodeServerFailure}
		}
		ips := []net.IP{}
		for _, rr := range entry.records {
			switch rr := rr.(type) {
			case *dns.A:
				ips = append(ips, rr.Addr.AsSlice())
			case *dns.AAAA:
				ips = append(ips, rr.Addr.AsSlice())
			}
		}
		return ips, nil
	}
	ips := &netapi.IPs{}
	var err4, err6 error
	if opt.Mode != netapi.ResolverModePreferIPv6 {
		ips.A, err4 = lookup(dns.TypeA, a, netapi.ResolverModePreferIPv4)
	}
	if opt.Mode != netapi.ResolverModePreferIPv4 {
		ips.AAAA, err6 = lookup(dns.TypeAAAA, aaaa, netapi.ResolverModePreferIPv6)
	}
	if len(ips.A)+len(ips.AAAA) > 0 {
		return ips, nil
	}
	if err := errors.Join(err4, err6); err != nil {
		return nil, err
	}
	return ips, nil
}

func (*Resolver) Close() error { return nil }
func (*Resolver) Name() string { return "custom DNS responses" }
