package sysnet

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/iface"
)

func viewRoute(t *testing.T, v sysnet.SystemRoutes, dst string) sysnet.SystemRouteEntry {
	t.Helper()
	for _, r := range v.Routes {
		if r.Destination == dst {
			return r
		}
	}
	t.Fatalf("no route %s in %+v", dst, v.Routes)
	return sysnet.SystemRouteEntry{}
}

func TestSystemRoutesMarksYuhaiinRoutes(t *testing.T) {
	n := newTestNet(t, sysnet.Config{Routes: []sysnet.RouteRule{rule("wg", 1, custom("10.10.0.0/16"), ifTarget("wg0"))}})
	n.attach("a", 10, false, "198.18.0.0/15")
	yh := netlink.RouteProtocolYuhaiin
	n.m.opts.ListRoutes = func() ([]netlink.RouteEntry, []netlink.PolicyRuleEntry, error) {
		return []netlink.RouteEntry{
			{Destination: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("192.168.1.1"), Link: 2, Table: 254, Type: "unicast"},
			{Destination: netip.MustParsePrefix("10.10.0.0/16"), Link: 5, Table: 63, Protocol: yh},
			{Destination: netip.MustParsePrefix("198.18.0.0/15"), Link: 10, Table: 63, Protocol: yh},
			{Destination: netip.MustParsePrefix("192.0.2.0/24"), Link: 5, Table: 63, Protocol: yh},
			// Same prefix as a rule route, but on another link and table.
			{Destination: netip.MustParsePrefix("10.10.0.0/16"), Link: 2, Table: 254},
		}, []netlink.PolicyRuleEntry{
			{Priority: 30001, Family: 2, Selector: "all", Table: 63},
			{Priority: 32766, Family: 2, Selector: "all", Table: 254},
		}, nil
	}
	v := n.m.SystemRoutes(t.Context())
	if !v.Readable || v.Total != 5 || v.YuhaiinRoutes != 3 {
		t.Fatalf("view = %+v", v)
	}
	if r := viewRoute(t, v, "0.0.0.0/0"); r.Yuhaiin || r.Interface != "eth0" || r.Gateway != "192.168.1.1" {
		t.Fatalf("default route = %+v", r)
	}
	for _, r := range v.Routes {
		if r.Destination != "10.10.0.0/16" {
			continue
		}
		if want := r.Table == 63; r.Yuhaiin != want || (want && (r.Source != sysnet.SourceRule || r.RuleID != "wg" || r.RuleName != "wg")) {
			t.Fatalf("rule route = %+v", r)
		}
	}
	if r := viewRoute(t, v, "198.18.0.0/15"); r.Source != sysnet.SourceRequired || r.RuleName != "TUN a" || r.Interface != "utuna" {
		t.Fatalf("required route = %+v", r)
	}
	if r := viewRoute(t, v, "192.0.2.0/24"); r.Source != sysnet.SourceStale {
		t.Fatalf("stale route = %+v", r)
	}
	if len(v.Rules) != 2 || !v.Rules[0].Yuhaiin || v.Rules[1].Yuhaiin {
		t.Fatalf("rules = %+v", v.Rules)
	}

	n.m.opts.ListRoutes = func() ([]netlink.RouteEntry, []netlink.PolicyRuleEntry, error) {
		return nil, nil, errors.New("denied")
	}
	if v := n.m.SystemRoutes(t.Context()); v.Readable || v.Error != "denied" {
		t.Fatalf("failed view = %+v", v)
	}
}

func TestSystemRoutesAndroid(t *testing.T) {
	var list func() ([]netlink.RouteEntry, []netlink.PolicyRuleEntry, error)
	m := New(Options{Capabilities: PlatformCapabilities("android", false, false),
		Interfaces: func() ([]iface.Info, error) { return nil, nil },
		ListRoutes: func() ([]netlink.RouteEntry, []netlink.PolicyRuleEntry, error) { return list() }})
	if err := m.SetStore(t.Context(), &memoryStore{config: sysnet.Config{Routes: []sysnet.RouteRule{rule("corp", 1, custom("10.0.0.0/8"), tunTarget("tun"))}}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	m.AttachTun(TunAttachment{InboundID: "tun", InboundName: "VPN", IPv4: true, Required: pfx("198.18.0.0/15"),
		Platform: func([]netip.Prefix, bool) error { return nil }})

	// The app reports the routes Android holds for each network.
	list = func() ([]netlink.RouteEntry, []netlink.PolicyRuleEntry, error) {
		return []netlink.RouteEntry{
			{Destination: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("192.168.1.1"), Interface: "wlan0"},
			{Destination: netip.MustParsePrefix("10.0.0.0/8"), Interface: "tun0", OwnVPN: true},
			{Destination: netip.MustParsePrefix("198.18.0.0/15"), Interface: "tun0", OwnVPN: true},
		}, nil, nil
	}
	v := m.SystemRoutes(t.Context())
	if !v.Readable || v.YuhaiinRoutes != 2 {
		t.Fatalf("view = %+v", v)
	}
	if r := viewRoute(t, v, "0.0.0.0/0"); r.Yuhaiin || r.Interface != "wlan0" {
		t.Fatalf("wifi route = %+v", r)
	}
	if r := viewRoute(t, v, "10.0.0.0/8"); r.Source != sysnet.SourceVPN || r.RuleName != "corp" || r.Interface != "tun0" {
		t.Fatalf("rule route = %+v", r)
	}
	if r := viewRoute(t, v, "198.18.0.0/15"); r.Source != sysnet.SourceRequired {
		t.Fatalf("required route = %+v", r)
	}

	// An app without the routes host call: show what the VPN received.
	list = func() ([]netlink.RouteEntry, []netlink.PolicyRuleEntry, error) {
		return nil, nil, errors.New("host call routes.list not registered")
	}
	v = m.SystemRoutes(t.Context())
	if v.Readable || v.YuhaiinRoutes == 0 || viewRoute(t, v, "10.0.0.0/8").RuleName != "corp" {
		t.Fatalf("fallback view = %+v", v)
	}
}
