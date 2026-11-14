package netlink

import (
	"net/netip"
	"testing"
)

var (
	en0 = ScopedInterface{Name: "en0", Index: 11, Up: true, Prefixes: []netip.Prefix{
		netip.MustParsePrefix("192.168.1.100/24"), netip.MustParsePrefix("2001:db8:1::100/64"), netip.MustParsePrefix("fe80::1/64")}}
	en5 = ScopedInterface{Name: "en5", Index: 15, Up: true, Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.20.100/24")}}
	tun = ScopedInterface{Name: "utun4", Index: 20, Up: true, OwnTun: true, Prefixes: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/16")}}
	lo  = ScopedInterface{Name: "lo0", Index: 1, Up: true, Loopback: true, Prefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")}}
)

func rib(dst, gw string, index int, scoped bool) RIBRoute {
	r := RIBRoute{Dst: netip.MustParsePrefix(dst), Index: index, Scoped: scoped}
	if gw != "" {
		r.Gateway = netip.MustParseAddr(gw)
	}
	return r
}

func find(plan []ScopedRoute, name string, v6 bool) ScopedRoute {
	for _, r := range plan {
		if r.Interface == name && r.IPv6 == v6 {
			return r
		}
	}
	return ScopedRoute{State: "absent"}
}

// The usual macOS table: global default on the primary, configd's scoped
// default on the secondary, a VPN's /1 routes on our TUN.
func TestScopedPlanUsualTable(t *testing.T) {
	table := []RIBRoute{
		rib("0.0.0.0/0", "192.168.1.1", 11, false),
		rib("::/0", "fe80::abcd", 11, false),
		rib("0.0.0.0/0", "192.168.20.1", 15, true),
		rib("0.0.0.0/1", "", 20, false),
		rib("128.0.0.0/1", "", 20, false),
	}
	p := newScopedPlanner()
	plan, create, remove := p.plan(table, []ScopedInterface{lo, en0, en5, tun}, nil)
	if len(create) != 0 || len(remove) != 0 {
		t.Fatalf("create %v remove %v, want nothing", create, remove)
	}
	for _, tc := range []struct {
		name  string
		v6    bool
		state string
		gw    string
	}{
		{"en0", false, ScopedPrimary, "192.168.1.1"},
		{"en0", true, ScopedPrimary, "fe80::abcd"},
		{"en5", false, ScopedBorrowed, "192.168.20.1"},
	} {
		got := find(plan, tc.name, tc.v6)
		if got.State != tc.state || got.Gateway.String() != tc.gw {
			t.Fatalf("%s v6=%v = %+v, want %s via %s", tc.name, tc.v6, got, tc.state, tc.gw)
		}
	}
	// Only one family configured: no IPv6 entry for en5; our TUN and
	// loopback are never planned.
	for _, absent := range []struct {
		name string
		v6   bool
	}{{"en5", true}, {"utun4", false}, {"lo0", false}} {
		if got := find(plan, absent.name, absent.v6); got.State != "absent" {
			t.Fatalf("%s v6=%v planned: %+v", absent.name, absent.v6, got)
		}
	}
}

// A VPN replaces the global default: en0 keeps working through a scoped
// default Yuhaiin creates from the router it remembered; it is removed again
// when it is no longer needed, and a route of the same prefix on another
// interface is never touched.
func TestScopedPlanRecreatesLostDefault(t *testing.T) {
	p := newScopedPlanner()
	before := []RIBRoute{rib("0.0.0.0/0", "192.168.1.1", 11, false), rib("0.0.0.0/0", "192.168.20.1", 15, true)}
	p.plan(before, []ScopedInterface{en0, en5}, nil)

	vpn := []RIBRoute{rib("0.0.0.0/0", "10.8.0.1", 30, false), rib("0.0.0.0/0", "192.168.20.1", 15, true)}
	plan, create, _ := p.plan(vpn, []ScopedInterface{en0, en5}, nil)
	if len(create) != 1 || create[0].Index != 11 || create[0].Gateway.String() != "192.168.1.1" || create[0].IPv6 {
		t.Fatalf("create = %+v, want scoped default via 192.168.1.1 on en0", create)
	}
	if got := find(plan, "en5", false); got.State != ScopedBorrowed {
		t.Fatalf("en5 = %+v", got)
	}

	// Installed: the RIB now shows it, and it is ours.
	owned := map[scopedKey]ownedScoped{{11, false}: {netip.MustParseAddr("192.168.1.1"), familyPrefixes(en0, false)}}
	installed := append(vpn, rib("0.0.0.0/0", "192.168.1.1", 11, true))
	plan, create, remove := p.plan(installed, []ScopedInterface{en0, en5}, owned)
	if got := find(plan, "en0", false); got.State != ScopedOwned || len(create) != 0 || len(remove) != 0 {
		t.Fatalf("en0 = %+v create %v remove %v", got, create, remove)
	}

	// The VPN goes away and the global default returns: ours is removed.
	_, _, remove = p.plan(append(before, rib("0.0.0.0/0", "192.168.1.1", 11, true)), []ScopedInterface{en0, en5}, owned)
	if len(remove) != 0 {
		// Still present and still ours (the scoped entry exists): kept.
		t.Fatalf("remove = %v", remove)
	}
	_, _, remove = p.plan(before, []ScopedInterface{en0, en5}, owned)
	if len(remove) != 1 || remove[0].Index != 11 {
		t.Fatalf("remove = %v, want our en0 route", remove)
	}
}

// Someone else's scoped default is borrowed, never claimed or removed.
func TestScopedPlanBorrowsForeignRoute(t *testing.T) {
	p := newScopedPlanner()
	owned := map[scopedKey]ownedScoped{{15, false}: {netip.MustParseAddr("192.168.20.254"), familyPrefixes(en5, false)}}
	table := []RIBRoute{rib("0.0.0.0/0", "192.168.20.1", 15, true)}
	plan, create, remove := p.plan(table, []ScopedInterface{en5}, owned)
	if got := find(plan, "en5", false); got.State != ScopedBorrowed {
		t.Fatalf("en5 = %+v", got)
	}
	if len(create) != 0 || len(remove) != 1 || remove[0].Gateway.String() != "192.168.20.254" {
		// Our record is stale (the route was replaced): forget it, but the
		// deletion only matches our gateway, never the borrowed route.
		t.Fatalf("create %v remove %v", create, remove)
	}
}

func TestScopedPlanNoGateway(t *testing.T) {
	p := newScopedPlanner()
	plan, create, _ := p.plan(nil, []ScopedInterface{en5}, nil)
	got := find(plan, "en5", false)
	if got.State != ScopedUnavailable || got.Reason == "" || len(create) != 0 {
		t.Fatalf("en5 without any router = %+v create %v", got, create)
	}
}

// A new network on the same interface invalidates the remembered router and
// our route made for the old one.
func TestScopedPlanNetworkChange(t *testing.T) {
	p := newScopedPlanner()
	p.plan([]RIBRoute{rib("0.0.0.0/0", "192.168.1.1", 11, false)}, []ScopedInterface{en0}, nil)
	moved := en0
	moved.Prefixes = []netip.Prefix{netip.MustParsePrefix("10.0.0.5/24")}
	plan, create, _ := p.plan(nil, []ScopedInterface{moved}, nil)
	if got := find(plan, "en0", false); got.State != ScopedUnavailable || len(create) != 0 {
		t.Fatalf("after network change = %+v create %v", got, create)
	}

	// Ours from the old network is still in the RIB: deleted.
	p2 := newScopedPlanner()
	owned := map[scopedKey]ownedScoped{{11, false}: {netip.MustParseAddr("192.168.1.1"), familyPrefixes(en0, false)}}
	plan, _, remove := p2.plan([]RIBRoute{rib("0.0.0.0/0", "192.168.1.1", 11, true)}, []ScopedInterface{moved}, owned)
	if got := find(plan, "en0", false); got.State != ScopedUnavailable || len(remove) != 1 {
		t.Fatalf("stale owned route = %+v remove %v", got, remove)
	}
}

// Down, removed and renumbered interfaces release our routes.
func TestScopedPlanInterfaceDownAndIndexChange(t *testing.T) {
	p := newScopedPlanner()
	p.plan([]RIBRoute{rib("0.0.0.0/0", "192.168.1.1", 11, false)}, []ScopedInterface{en0}, nil)
	owned := map[scopedKey]ownedScoped{{11, false}: {netip.MustParseAddr("192.168.1.1"), familyPrefixes(en0, false)}}
	down := en0
	down.Up = false
	if _, _, remove := p.plan(nil, []ScopedInterface{down}, owned); len(remove) != 1 {
		t.Fatalf("down interface kept our route: %v", remove)
	}
	renumbered := en0
	renumbered.Index = 12
	plan, create, remove := p.plan(nil, []ScopedInterface{renumbered}, owned)
	if len(remove) != 1 || remove[0].Index != 11 {
		t.Fatalf("old index not released: %v", remove)
	}
	// The new index has no remembered router of its own.
	if got := find(plan, "en0", false); got.State != ScopedUnavailable || len(create) != 0 {
		t.Fatalf("renumbered = %+v create %v", got, create)
	}
}

// IPv6 scoped defaults are planned independently, with link-local routers.
func TestScopedPlanIPv6(t *testing.T) {
	p := newScopedPlanner()
	p.plan([]RIBRoute{rib("::/0", "fe80::abcd", 11, false), rib("0.0.0.0/0", "192.168.1.1", 11, false)}, []ScopedInterface{en0}, nil)
	// Only the IPv6 default disappears.
	plan, create, _ := p.plan([]RIBRoute{rib("0.0.0.0/0", "192.168.1.1", 11, false)}, []ScopedInterface{en0}, nil)
	if got := find(plan, "en0", false); got.State != ScopedPrimary {
		t.Fatalf("IPv4 = %+v", got)
	}
	if len(create) != 1 || !create[0].IPv6 || create[0].Gateway.String() != "fe80::abcd" {
		t.Fatalf("create = %+v, want IPv6 scoped default via fe80::abcd", create)
	}
}
