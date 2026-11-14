//go:build linux && !android

package netlink

import (
	"net/netip"
	"os"
	"runtime"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// isolatedNamespace enters a fresh network namespace, or, inside a container
// started by scripts/integration/system-network-podman.sh, uses the
// container's own namespace. Test routes are never installed on the host.
func isolatedNamespace(t *testing.T) {
	t.Helper()
	if os.Getenv("YUHAIIN_TEST_TUN_ROUTES") != "1" {
		t.Skip("set YUHAIIN_TEST_TUN_ROUTES=1 in a Linux environment with network namespace privileges")
	}
	if os.Getenv("YUHAIIN_TEST_ISOLATED_CONTAINER") == "1" {
		return
	}
	runtime.LockOSThread()
	original, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	isolated, err := netns.New()
	if err != nil {
		runtime.UnlockOSThread()
		t.Skipf("isolated network namespace unavailable: %v", err)
	}
	t.Cleanup(func() {
		_ = netns.Set(original)
		_ = isolated.Close()
		_ = original.Close()
		runtime.UnlockOSThread()
	})
}

func dummyLink(t *testing.T, name, address string) int {
	t.Helper()
	_ = netlink.LinkDel(&netlink.Dummy{Name: name})
	if err := netlink.LinkAdd(&netlink.Dummy{Name: name}); err != nil {
		t.Fatal(err)
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(link) })
	if address != "" {
		addr, err := netlink.ParseAddr(address)
		if err != nil {
			t.Fatal(err)
		}
		if err := netlink.AddrAdd(link, addr); err != nil {
			t.Fatal(err)
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	return link.Attrs().Index
}

func tableRoutes(t *testing.T, p string) []netlink.Route {
	t.Helper()
	prefix := netip.MustParsePrefix(p)
	found, err := netlink.RouteListFiltered(family(prefix), &netlink.Route{Table: tunRouteTable, Dst: ipNet(prefix)}, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_DST)
	if err != nil {
		t.Fatal(err)
	}
	return found
}

func hasRule(t *testing.T, f, priority int) bool {
	t.Helper()
	rules, err := netlink.RuleList(f)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if r.Priority == priority && r.Table == tunRouteTable {
			return true
		}
	}
	return false
}

func TestLinuxSystemRoutesInNamespace(t *testing.T) {
	isolatedNamespace(t)
	tunA := dummyLink(t, "yhtesta", "172.19.0.1/24")
	tunB := dummyLink(t, "yhtestb", "172.20.0.1/24")
	lan := dummyLink(t, "yhtestlan", "192.168.77.2/24")
	if err := netlink.AddrAdd(mustLink(t, "yhtesta"), mustAddr(t, "fd00:a::1/64")); err != nil {
		t.Fatal(err)
	}

	// A route another program put in the dedicated table is never touched;
	// asking for the same prefix on another interface is a conflict.
	foreign := netlink.Route{LinkIndex: tunB, Table: tunRouteTable, Dst: ipNet(netip.MustParsePrefix("203.0.113.0/24"))}
	if err := netlink.RouteAdd(&foreign); err != nil {
		t.Fatal(err)
	}
	// A route left by a crashed run (our protocol) is removed on start.
	stale := netlink.Route{LinkIndex: tunA, Table: tunRouteTable, Protocol: routeProtocol, Dst: ipNet(netip.MustParsePrefix("198.51.100.0/24"))}
	if err := netlink.RouteAdd(&stale); err != nil {
		t.Fatal(err)
	}

	m, err := NewRouteManager()
	if err != nil {
		t.Fatal(err)
	}
	if len(tableRoutes(t, "198.51.100.0/24")) != 0 {
		t.Fatal("stale owned route survived manager start")
	}
	desired := append(append(append(via(tunA, "", "0.0.0.0/1", "8.8.8.0/24", "2001:4860::/32"),
		via(tunB, "", "10.10.0.0/16")...),
		via(lan, "192.168.77.1", "192.0.2.0/24")...),
		via(tunA, "", "203.0.113.0/24")...)
	conflicts, err := m.Update(desired)
	if err != nil {
		t.Fatal(err)
	}
	if len(conflicts) != 1 || conflicts[0] != netip.MustParsePrefix("203.0.113.0/24") {
		t.Fatalf("conflicts = %v", conflicts)
	}
	for p, link := range map[string]int{"0.0.0.0/1": tunA, "8.8.8.0/24": tunA, "2001:4860::/32": tunA, "10.10.0.0/16": tunB, "192.0.2.0/24": lan} {
		routes := tableRoutes(t, p)
		if len(routes) != 1 || routes[0].LinkIndex != link || routes[0].Protocol != routeProtocol {
			t.Fatalf("route %s = %+v, want link %d", p, routes, link)
		}
	}
	if routes := tableRoutes(t, "203.0.113.0/24"); len(routes) != 1 || routes[0].LinkIndex != tunB || routes[0].Protocol == routeProtocol {
		t.Fatalf("foreign route changed: %+v", routes)
	}
	if gw := tableRoutes(t, "192.0.2.0/24")[0].Gw.String(); gw != "192.168.77.1" {
		t.Fatalf("gateway = %s", gw)
	}
	if !hasRule(t, unix.AF_INET, ruleV4) || !hasRule(t, unix.AF_INET6, ruleV6) {
		t.Fatal("policy rules missing")
	}
	// The kernel resolves destinations through the policy rule and table.
	for dst, link := range map[string]int{"8.8.8.8": tunA, "10.10.1.1": tunB, "192.0.2.9": lan} {
		got, err := netlink.RouteGet(netip.MustParseAddr(dst).AsSlice())
		if err != nil || len(got) == 0 || got[0].LinkIndex != link {
			t.Fatalf("lookup %s = %+v %v, want link %d", dst, got, err, link)
		}
	}

	// The routes view reads both tables and marks our routes and rules.
	entries, rules, err := ListRoutes()
	if err != nil {
		t.Fatal(err)
	}
	ours := map[string]bool{}
	for _, e := range entries {
		if e.Table == tunRouteTable {
			ours[e.Destination.String()] = e.Protocol == RouteProtocolYuhaiin
		}
	}
	if !ours["8.8.8.0/24"] || !ours["2001:4860::/32"] || ours["203.0.113.0/24"] {
		t.Fatalf("table %d in routes view = %v", tunRouteTable, ours)
	}
	ownedRules := 0
	for _, r := range rules {
		if r.Table == tunRouteTable && r.Protocol == RouteProtocolYuhaiin {
			ownedRules++
		}
	}
	if ownedRules != 2 {
		t.Fatalf("policy rules in routes view = %+v", rules)
	}

	// Moving a prefix between targets replaces it in place.
	desired[1] = SystemRoute{Prefix: netip.MustParsePrefix("8.8.8.0/24"), Link: tunB}
	if _, err := m.Update(desired); err != nil {
		t.Fatal(err)
	}
	if routes := tableRoutes(t, "8.8.8.0/24"); len(routes) != 1 || routes[0].LinkIndex != tunB {
		t.Fatalf("moved route = %+v", routes)
	}

	// A disappearing interface takes its routes; the next update tolerates it.
	if err := netlink.LinkDel(mustLink(t, "yhtestb")); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Update(via(tunA, "", "0.0.0.0/1", "2001:4860::/32")); err != nil {
		t.Fatalf("update after interface removal: %v", err)
	}
	if len(tableRoutes(t, "8.8.8.0/24")) != 0 || len(tableRoutes(t, "192.0.2.0/24")) != 0 {
		t.Fatal("obsolete routes kept")
	}

	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if len(tableRoutes(t, "0.0.0.0/1")) != 0 || len(tableRoutes(t, "2001:4860::/32")) != 0 {
		t.Fatal("owned routes kept after close")
	}
	if hasRule(t, unix.AF_INET, ruleV4) || hasRule(t, unix.AF_INET6, ruleV6) {
		t.Fatal("owned policy rules kept after close")
	}
}

func mustLink(t *testing.T, name string) netlink.Link {
	t.Helper()
	link, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatal(err)
	}
	return link
}

func mustAddr(t *testing.T, s string) *netlink.Addr {
	t.Helper()
	a, err := netlink.ParseAddr(s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
