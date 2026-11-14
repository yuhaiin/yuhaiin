package sysnet

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer/interfaces"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/iface"
)

func fakeOutbound(goos string) outboundSources {
	return outboundSources{
		goos:       goos,
		protection: func() dialer.ProtectionReport { return dialer.ProtectionReport{} },
		ownTuns:    func() []string { return []string{"tun0"} },
		configured: func() string { return "" },
		selectRoute: func(dst netip.Addr, exclude func(string) bool) (interfaces.RouteChoice, bool) {
			if exclude("eth0") {
				return interfaces.RouteChoice{}, false
			}
			p := netip.MustParsePrefix("0.0.0.0/0")
			if dst.Is6() {
				p = netip.MustParsePrefix("::/0")
			}
			return interfaces.RouteChoice{Interface: "eth0", Prefix: p, Gateway: netip.MustParseAddr("192.168.1.1"), Metric: 25}, true
		},
		defaults: func() []interfaces.RouteChoice {
			return []interfaces.RouteChoice{{Interface: "eth0", Prefix: netip.MustParsePrefix("0.0.0.0/0"), Metric: 25}}
		},
		rules:       func() ([]netlink.ProtectionRule, error) { return nil, nil },
		mainViaTun:  func([]int) ([]netip.Prefix, error) { return nil, nil },
		tableRoutes: func() int { return 0 },
		interfaces: func() ([]iface.Info, error) {
			return []iface.Info{
				{Name: "lo", Type: iface.TypeLoopback, Up: true},
				{Name: "eth0", Index: 2, Type: iface.TypeEthernet, Up: true, Addresses: []netip.Prefix{netip.MustParsePrefix("192.168.1.2/24")}, Gateway: netip.MustParseAddr("192.168.1.1")},
				{Name: "tun0", Index: 9, Type: iface.TypeTunnel, Up: true},
				{Name: "wg0", Index: 10, Type: iface.TypeTunnel, Up: true},
			}, nil
		},
	}
}

func markOK() dialer.ProtectionReport {
	return dialer.ProtectionReport{Installed: true, Method: "SO_MARK", Mark: 0x500, Successes: 12}
}

func TestOutboundLinuxActive(t *testing.T) {
	src := fakeOutbound("linux")
	src.protection = markOK
	src.tableRoutes = func() int { return 4 }
	src.rules = func() ([]netlink.ProtectionRule, error) {
		return []netlink.ProtectionRule{{Priority: 30001, Table: 63, Selector: "not fwmark 0x500 lookup 63", Present: true},
			{IPv6: true, Priority: 30002, Table: 63, Selector: "not fwmark 0x500 lookup 63", Present: true}}, nil
	}
	got := buildOutboundRouting(src, map[string]int{"tun0": 9})
	if got.State != sysnet.StateActive || !got.ProtectionActive || got.EgressMode != sysnet.EgressKernel || got.Mark != 0x500 {
		t.Fatalf("status = %+v", got)
	}
	if len(got.Rules) != 2 || got.Rules[0].State != sysnet.StateActive || got.Rules[1].State != sysnet.StateActive {
		t.Fatalf("rules = %+v", got.Rules)
	}
	if got.Egress[0].Interface != "eth0" || got.Egress[0].Gateway != "192.168.1.1" {
		t.Fatalf("egress = %+v", got.Egress)
	}
	owner := map[string]string{}
	for _, i := range got.Interfaces {
		owner[i.Name] = i.Ownership
		if i.Name == "tun0" && !i.Excluded {
			t.Fatal("own TUN not excluded")
		}
	}
	if owner["lo"] != "" || owner["tun0"] != sysnet.OwnerYuhaiin || owner["wg0"] != sysnet.OwnerExternal || owner["eth0"] != sysnet.OwnerSystem {
		t.Fatalf("ownership = %v", owner)
	}
}

// SO_MARK without the capability while a TUN runs: never shown as active.
func TestOutboundLinuxMarkUnavailable(t *testing.T) {
	src := fakeOutbound("linux")
	src.protection = func() dialer.ProtectionReport {
		return dialer.ProtectionReport{Method: "SO_MARK", Mark: 0x500, Unavailable: "setting SO_MARK needs CAP_NET_ADMIN"}
	}
	got := buildOutboundRouting(src, nil)
	if got.State != sysnet.StateDegraded || got.ProtectionActive || got.EgressMode != sysnet.EgressBound {
		t.Fatalf("status = %+v", got)
	}
	if len(got.Problems) == 0 || !strings.Contains(got.Problems[0], "CAP_NET_ADMIN") {
		t.Fatalf("problems = %v", got.Problems)
	}

	src.ownTuns = func() []string { return nil }
	if got := buildOutboundRouting(src, nil); got.State != sysnet.StateUnavailable || got.EgressMode != sysnet.EgressSystem {
		t.Fatalf("without TUN = %+v", got)
	}
}

func TestOutboundLinuxRuleProblems(t *testing.T) {
	src := fakeOutbound("linux")
	src.protection = markOK
	src.tableRoutes = func() int { return 4 }
	src.rules = func() ([]netlink.ProtectionRule, error) {
		return []netlink.ProtectionRule{{Priority: 30001, Table: 63, Old: true}, {IPv6: true, Priority: 30002, Table: 63}}, nil
	}
	got := buildOutboundRouting(src, map[string]int{"tun0": 9})
	if got.State != sysnet.StateFailed || got.Rules[0].State != sysnet.StateFailed || got.Rules[1].State != sysnet.StateFailed {
		t.Fatalf("status = %+v rules %+v", got.State, got.Rules)
	}

	// Main-table routes through our TUN degrade it.
	src.rules = func() ([]netlink.ProtectionRule, error) {
		return []netlink.ProtectionRule{{Priority: 30001, Present: true}}, nil
	}
	src.mainViaTun = func(links []int) ([]netip.Prefix, error) {
		if len(links) != 1 || links[0] != 9 {
			t.Fatalf("links = %v", links)
		}
		return []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, nil
	}
	if got := buildOutboundRouting(src, map[string]int{"tun0": 9}); got.State != sysnet.StateDegraded {
		t.Fatalf("main via TUN = %+v", got)
	}
}

func TestOutboundDarwinScoped(t *testing.T) {
	src := fakeOutbound("darwin")
	src.scopedRoutes = func() ([]netlink.ScopedRoute, error) {
		return []netlink.ScopedRoute{
			{Interface: "eth0", State: netlink.ScopedPrimary, Gateway: netip.MustParseAddr("192.168.1.1")},
			{Interface: "eth0", IPv6: true, State: netlink.ScopedFailed, Reason: "permission denied"},
		}, nil
	}
	got := buildOutboundRouting(src, nil)
	if got.Method != "IP_BOUND_IF / IPV6_BOUND_IF" || got.EgressMode != sysnet.EgressBound {
		t.Fatalf("status = %+v", got)
	}
	if got.State != sysnet.StateDegraded {
		t.Fatalf("a failed scoped route must degrade: %+v", got)
	}
	for _, i := range got.Interfaces {
		if i.Name == "eth0" && (i.Scoped.State != netlink.ScopedPrimary || i.ScopedV6.State != netlink.ScopedFailed) {
			t.Fatalf("eth0 = %+v", i)
		}
	}
}

func TestOutboundNoEgressFails(t *testing.T) {
	src := fakeOutbound("windows")
	src.selectRoute = func(netip.Addr, func(string) bool) (interfaces.RouteChoice, bool) {
		return interfaces.RouteChoice{}, false
	}
	got := buildOutboundRouting(src, nil)
	if got.State != sysnet.StateFailed || got.Egress[0].Error == "" {
		t.Fatalf("status = %+v", got)
	}
	// An explicit interface is reported as such.
	src.configured = func() string { return "eth0" }
	if got := buildOutboundRouting(src, nil); got.EgressMode != sysnet.EgressExplicit || got.Egress[0].Interface != "eth0" {
		t.Fatalf("explicit = %+v", got)
	}
}

func TestOutboundWindowsMetrics(t *testing.T) {
	got := buildOutboundRouting(fakeOutbound("windows"), nil)
	if got.Method != "IP_UNICAST_IF / IPV6_UNICAST_IF" || got.Egress[0].Metric != 25 {
		t.Fatalf("status = %+v", got)
	}
	for _, i := range got.Interfaces {
		if i.Name == "eth0" && i.DefaultMetric != 25 {
			t.Fatalf("eth0 metric = %d", i.DefaultMetric)
		}
	}
}

func TestOutboundUnsupported(t *testing.T) {
	if got := buildOutboundRouting(fakeOutbound("plan9"), nil); got.State != sysnet.StateUnsupported {
		t.Fatalf("status = %+v", got)
	}
}
