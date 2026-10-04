//go:build linux && !android

package netlink

import (
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// Opt-in and namespace-only: never install test routes in the host namespace.
func TestLinuxRouteLifecycleInNamespace(t *testing.T) {
	if os.Getenv("YUHAIIN_TEST_TUN_ROUTES") != "1" {
		t.Skip("set YUHAIIN_TEST_TUN_ROUTES=1 in a Linux environment with network namespace privileges")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	original, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	isolated, err := netns.New()
	if err != nil {
		t.Skipf("isolated network namespace unavailable: %v", err)
	}
	defer isolated.Close()
	defer func() {
		if err := netns.Set(original); err != nil {
			t.Fatal(err)
		}
	}()
	for _, name := range []string{"testtun1", "testtun2"} {
		if err := netlink.LinkAdd(&netlink.Dummy{Name: name}); err != nil {
			t.Fatal(err)
		}
	}
	firstLink, err := netlink.LinkByName("testtun1")
	if err != nil {
		t.Fatal(err)
	}
	borrowed := netlink.Route{LinkIndex: firstLink.Attrs().Index, Table: tunRouteTable, Dst: netipIPNet(netip.MustParsePrefix("192.0.2.0/24"))}
	if err := netlink.RouteAdd(&borrowed); err != nil {
		t.Fatal(err)
	}
	first := &Options{Interface: TunScheme{Scheme: "tun", Name: "testtun1"}, MTU: 1500, Inet4Address: prefixes("172.19.0.1/24"), Inet6Address: prefixes("fd00::1/64"), Routes: prefixes("192.0.2.0/24", "198.18.0.0/16", "2001:2::/64")}
	cleanup1, err := Route(first)
	if cleanup1 != nil {
		defer cleanup1()
	}
	if err != nil {
		t.Fatal(err)
	}
	second := &Options{Interface: TunScheme{Scheme: "tun", Name: "testtun2"}, MTU: 1500, Inet4Address: prefixes("172.20.0.1/24"), Routes: prefixes("198.19.0.0/16")}
	cleanup2, err := Route(second)
	if cleanup2 != nil {
		defer cleanup2()
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := first.RouteManager.Update(prefixes("192.0.2.0/24", "198.20.0.0/16", "2001:2:0:1::/64")); err != nil {
		t.Fatal(err)
	}
	assertLinuxRoute := func(prefix string, present bool) {
		t.Helper()
		p := netip.MustParsePrefix(prefix)
		family := unix.AF_INET6
		if p.Addr().Is4() {
			family = unix.AF_INET
		}
		found, err := netlink.RouteListFiltered(family, &netlink.Route{Table: tunRouteTable, Dst: netipIPNet(p)}, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_DST)
		if err != nil || (len(found) > 0) != present {
			t.Fatalf("route %s present=%v, want %v, err=%v", prefix, len(found) > 0, present, err)
		}
	}
	assertLinuxRoute("198.18.0.0/16", false)
	assertLinuxRoute("2001:2::/64", false)
	assertLinuxRoute("198.20.0.0/16", true)
	assertLinuxRoute("2001:2:0:1::/64", true)
	if err := first.RouteManager.Close(); err != nil {
		t.Fatal(err)
	}
	assertLinuxRoute("198.20.0.0/16", false)
	assertLinuxRoute("192.0.2.0/24", true)  // preexisting route was borrowed
	assertLinuxRoute("198.19.0.0/16", true) // second TUN is still active
	rules, err := netlink.RuleList(unix.AF_INET)
	if err != nil {
		t.Fatal(err)
	}
	sharedRule := false
	for _, r := range rules {
		if r.Priority == 30001 && r.Table == tunRouteTable {
			sharedRule = true
		}
	}
	if !sharedRule {
		t.Fatal("closing the first TUN removed the shared policy rule")
	}
	if err := second.RouteManager.Close(); err != nil {
		t.Fatal(err)
	}
	rules, err = netlink.RuleList(unix.AF_INET)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if r.Priority == 30001 && r.Table == tunRouteTable {
			t.Fatal("owned policy rule remained after the last TUN closed")
		}
	}
}

func netipIPNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}
