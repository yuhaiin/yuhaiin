package fakeip

import (
	"net/netip"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/svcb"
)

func TestRewriteHTTPSHintsPreservesServiceParameters(t *testing.T) {
	old := netip.MustParseAddr("203.0.113.8")
	new4 := netip.MustParseAddr("198.18.0.8")
	new6 := netip.MustParseAddr("2001:2::8")
	service := &dns.HTTPS{SVCB: dns.SVCB{
		Hdr: dns.Header{Name: "example.com.", Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, TTL: 60},
		Priority: 1, Target: ".",
		Value: []svcb.Pair{&svcb.IPV4HINT{Hint: []netip.Addr{old}}},
	}}
	alias := &dns.HTTPS{SVCB: dns.SVCB{
		Hdr: dns.Header{Name: "alias.example.", Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, TTL: 60},
		Priority: 0, Target: "example.com.",
	}}
	signature := &dns.RRSIG{Hdr: dns.Header{Name: "example.com.", Rrtype: dns.TypeRRSIG}, TypeCovered: dns.TypeHTTPS}
	msg := &dns.Msg{Answer: []dns.RR{alias, service, signature}}
	msg.AuthenticatedData = true

	rewriteHTTPSHints(msg, new4, new6)
	if msg.AuthenticatedData {
		t.Fatal("synthetic HTTPS answer retains the upstream AD bit")
	}
	if len(msg.Answer) != 2 {
		t.Fatalf("upstream signature not removed: %v", msg.Answer)
	}
	if msg.Answer[0] != alias || len(alias.Value) != 0 {
		t.Fatal("AliasMode was mutated or given service parameters")
	}
	out := msg.Answer[1].(*dns.HTTPS)
	if out == service {
		t.Fatal("mutated upstream cached HTTPS record in place")
	}
	if len(service.Value) != 1 || svcb.PairToKey(service.Value[0]) != svcb.KeyIPv4Hint {
		t.Fatalf("original response changed: %v", service.Value)
	}
	count4, count6 := 0, 0
	for _, param := range out.Value {
		switch h := param.(type) {
		case *svcb.IPV4HINT:
			count4++
			if len(h.Hint) != 1 || h.Hint[0] != new4 {
				t.Fatalf("wrong replacement IPv4 hint: %v", h.Hint)
			}
		case *svcb.IPV6HINT:
			count6++
			if len(h.Hint) != 1 || h.Hint[0] != new6 {
				t.Fatalf("wrong replacement IPv6 hint: %v", h.Hint)
			}
		}
	}
	if count4 != 1 || count6 != 1 {
		t.Fatalf("expected exactly one hint per family, got %d/%d", count4, count6)
	}
}

func TestRewriteHTTPSHintsWithoutServiceModeDoesNotAllocate(t *testing.T) {
	alias := &dns.HTTPS{SVCB: dns.SVCB{
		Hdr: dns.Header{Name: "example.com.", Rrtype: dns.TypeHTTPS},
		Priority: 0, Target: "alias.example.com.",
	}}
	msg := &dns.Msg{Answer: []dns.RR{alias}}
	rewriteHTTPSHints(msg, netip.MustParseAddr("198.18.0.10"), netip.Addr{})
	if len(msg.Answer) != 1 || msg.Answer[0] != alias || len(alias.Value) != 0 {
		t.Fatalf("AliasMode mutated: %v", msg.Answer)
	}
}
