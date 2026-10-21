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
	service := &dns.HTTPS{}
	service.Hdr = dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 60}
	service.Priority = 1
	service.Target = "."
	service.Value = []svcb.Pair{&svcb.IPV4HINT{Hint: []netip.Addr{old}}}
	alias := &dns.HTTPS{}
	alias.Hdr = dns.Header{Name: "alias.example.", Class: dns.ClassINET, TTL: 60}
	alias.Priority = 0
	alias.Target = "example.com."
	signature := &dns.RRSIG{}
	signature.Hdr = dns.Header{Name: "example.com.", Class: dns.ClassINET}
	signature.TypeCovered = dns.TypeHTTPS
	msg := &dns.Msg{Answer: []dns.RR{alias, service, signature}}
	msg.AuthenticatedData = true

	rewriteHTTPSHints(msg, "example.com.", new4, new6)
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
	alias := &dns.HTTPS{}
	alias.Hdr = dns.Header{Name: "example.com.", Class: dns.ClassINET}
	alias.Priority = 0
	alias.Target = "alias.example.com."
	msg := &dns.Msg{Answer: []dns.RR{alias}}
	rewriteHTTPSHints(msg, "example.com.", netip.MustParseAddr("198.18.0.10"), netip.Addr{})
	if len(msg.Answer) != 1 || msg.Answer[0] != alias || len(alias.Value) != 0 {
		t.Fatalf("AliasMode mutated: %v", msg.Answer)
	}
}

func TestRewriteHTTPSHintsAlternateTargetAndMandatory(t *testing.T) {
	alt := &dns.HTTPS{}
	alt.Hdr = dns.Header{Name: "example.com.", Class: dns.ClassINET}
	alt.Priority = 1
	alt.Target = "cdn.example.net."
	alt.Value = []svcb.Pair{
		&svcb.ALPN{Alpn: []string{"h3"}},
		&svcb.IPV4HINT{Hint: []netip.Addr{netip.MustParseAddr("203.0.113.4")}},
	}
	mandatory := &dns.HTTPS{}
	mandatory.Hdr = dns.Header{Name: "example.com.", Class: dns.ClassINET}
	mandatory.Priority = 2
	mandatory.Target = "cdn2.example.net."
	mandatory.Value = []svcb.Pair{
		&svcb.MANDATORY{Key: []uint16{svcb.KeyIPv4Hint}},
		&svcb.IPV4HINT{Hint: []netip.Addr{netip.MustParseAddr("203.0.113.5")}},
	}
	msg := &dns.Msg{Answer: []dns.RR{alt, mandatory}}
	rewriteHTTPSHints(msg, "example.com.", netip.MustParseAddr("198.18.0.8"), netip.MustParseAddr("2001:2::8"))
	if len(msg.Answer) != 1 {
		t.Fatalf("mandatory hint with alternate target must be suppressed: %v", msg.Answer)
	}
	got := msg.Answer[0].(*dns.HTTPS)
	if got == alt || got.Target != alt.Target || len(got.Value) != 1 || svcb.PairToKey(got.Value[0]) != svcb.KeyAlpn {
		t.Fatalf("unexpected alternate-target rewrite: %v", got)
	}
	if len(alt.Value) != 2 {
		t.Fatal("upstream alternate-target record mutated")
	}
}

func TestRewriteHTTPSHintsIPv6DisabledMandatory(t *testing.T) {
	record := &dns.HTTPS{}
	record.Hdr = dns.Header{Name: "example.com.", Class: dns.ClassINET}
	record.Priority = 1
	record.Target = "."
	record.Value = []svcb.Pair{&svcb.MANDATORY{Key: []uint16{svcb.KeyIPv6Hint}}}
	msg := &dns.Msg{Answer: []dns.RR{record}}
	rewriteHTTPSHints(msg, "example.com.", netip.MustParseAddr("198.18.0.8"), netip.Addr{})
	if len(msg.Answer) != 0 {
		t.Fatal("missing mandatory ipv6hint was left in response")
	}
}

func TestRewriteHTTPSHintsRespectsAliasOwner(t *testing.T) {
	for _, aliasType := range []string{"HTTPS", "CNAME"} {
		t.Run(aliasType, func(t *testing.T) {
			service := &dns.HTTPS{}
			service.Hdr = dns.Header{Name: "service.example.", Class: dns.ClassINET}
			service.Priority = 1
			service.Target = "."
			service.Value = []svcb.Pair{&svcb.IPV4HINT{Hint: []netip.Addr{netip.MustParseAddr("203.0.113.8")}}}
			var alias dns.RR
			if aliasType == "CNAME" {
				alias = &dns.CNAME{Hdr: dns.Header{Name: "origin.example.", Class: dns.ClassINET}, Target: "service.example."}
			} else {
				https := &dns.HTTPS{}
				https.Hdr = dns.Header{Name: "origin.example.", Class: dns.ClassINET}
				https.Target = "service.example."
				alias = https
			}
			msg := &dns.Msg{Answer: []dns.RR{alias, service}}
			fakeIP := netip.MustParseAddr("198.18.0.8")
			rewriteHTTPSHints(msg, "origin.example.", fakeIP, netip.Addr{})
			if msg.Answer[0] != alias {
				t.Fatal("alias record was changed")
			}
			out := msg.Answer[1].(*dns.HTTPS)
			if aliasType == "HTTPS" {
				if len(out.Value) != 0 {
					t.Fatalf("HTTPS alias target received the origin's FakeIP hint: %v", out.Value)
				}
			} else {
				if len(out.Value) != 1 {
					t.Fatalf("CNAME target lost its origin's FakeIP hint: %v", out.Value)
				}
				hint, ok := out.Value[0].(*svcb.IPV4HINT)
				if !ok || len(hint.Hint) != 1 || hint.Hint[0] != fakeIP {
					t.Fatalf("unexpected CNAME target hint: %v", out.Value)
				}
			}
		})
	}
}
