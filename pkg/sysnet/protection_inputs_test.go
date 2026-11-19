package sysnet

import (
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection"
)

type inputSink struct {
	mu   sync.Mutex
	last protection.Inputs
	n    int
}

func (s *inputSink) set(in protection.Inputs) { s.mu.Lock(); s.last, s.n = in, s.n+1; s.mu.Unlock() }
func (s *inputSink) get() protection.Inputs   { s.mu.Lock(); defer s.mu.Unlock(); return s.last }

func contains(list []netip.Prefix, addr string) bool {
	a := netip.MustParseAddr(addr)
	return slices.ContainsFunc(list, func(p netip.Prefix) bool { return p.Contains(a) })
}

func TestProtectionInputsFollowEffectiveRouting(t *testing.T) {
	n := newTestNet(t, sysnet.Config{Routes: []sysnet.RouteRule{
		rule("vpn", 100, sysnet.RouteMatch{Mode: sysnet.ModeNonPrivate, BypassCIDRs: []string{"203.0.113.0/24", "10.1.0.0/16", "0.0.0.0/0"}}, tunTarget("a")),
		rule("geo", 150, sysnet.RouteMatch{Mode: sysnet.ModeCustom, GeoIPCountries: []string{"CN"}, GeoIPInvert: true}, tunTarget("a")),
		rule("wg", 50, custom("198.51.100.0/24", "2001:db8:10::/48"), ifTarget("wg0")),
		rule("shadowed", 250, custom("8.8.8.0/24"), ifTarget("eth0")),
		rule("eth-all", 300, sysnet.RouteMatch{Mode: sysnet.ModeGlobal}, ifTarget("eth0")),
		{ID: "off", Name: "off", Enabled: false, Priority: 50, Match: sysnet.RouteMatch{Mode: sysnet.ModeGlobal, BypassCIDRs: []string{"192.0.2.0/24"}}, Target: tunTarget("a")},
	}})
	sink := &inputSink{}
	n.m.SetProtection(sink.set)
	n.attach("a", 10, true)
	in := sink.get()
	// Explicit bypass of a TUN rule, the GeoIP countries kept direct, and
	// destinations routed to another interface are allowed.
	for _, addr := range []string{"203.0.113.9", "1.0.16.1", "2001:db8:10::1", "198.51.100.1"} {
		if !contains(in.Bypass, addr) {
			t.Errorf("%s not in bypass %v", addr, in.Bypass)
		}
	}
	// 8.8.8.0/24 belongs to the higher-priority non_private TUN rule, so
	// the later interface rule does not own it and it is not a bypass.
	// Private networks are allowed separately, disabled rules and default
	// routes never become a bypass, and a whole-Internet interface rule is
	// reported instead.
	for _, addr := range []string{"10.1.0.1", "192.0.2.1", "8.8.8.8"} {
		if contains(in.Bypass, addr) {
			t.Errorf("%s in bypass", addr)
		}
	}
	for _, p := range in.Bypass {
		if p.Bits() == 0 {
			t.Fatal("default route in bypass")
		}
	}
	joined := strings.Join(in.Ignored, "\n")
	if !strings.Contains(joined, "whole Internet") || !strings.Contains(joined, "0.0.0.0/0") {
		t.Errorf("ignored = %v", in.Ignored)
	}
	if !slices.Equal(in.Tunnels, []protection.Tunnel{{Name: "utuna", IPv4: true, IPv6: true}}) {
		t.Errorf("tunnels = %+v", in.Tunnels)
	}
	if err := (protection.Policy{Mode: sysnet.ProtectionModeStandard, BypassNetworks: in.Bypass}).Validate(); err != nil {
		t.Fatalf("inputs produce an invalid policy: %v", err)
	}
	// The TUN stops: it leaves the inputs at once.
	n.m.DetachTun("a")
	if got := sink.get().Tunnels; len(got) != 0 {
		t.Fatalf("tunnels after detach = %+v", got)
	}
}
