package netlink

import (
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Live route test for a Mac: adds and removes routes for documentation
// prefixes through lo0. Runs only with YUHAIIN_TEST_DARWIN_LIVE=1 as root.
func TestDarwinLiveRoutes(t *testing.T) {
	if os.Getenv("YUHAIIN_TEST_DARWIN_LIVE") != "1" || os.Geteuid() != 0 {
		t.Skip("set YUHAIIN_TEST_DARWIN_LIVE=1 and run as root")
	}
	lo, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewRouteManager()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	routes := []SystemRoute{
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), Link: lo.Index, Gateway: netip.MustParseAddr("127.0.0.1")},
		{Prefix: netip.MustParsePrefix("2001:db8:77::/48"), Link: lo.Index, Gateway: netip.MustParseAddr("::1")},
	}
	if _, err := m.Update(routes); err != nil {
		t.Fatal(err)
	}
	show := func(args ...string) string {
		out, _ := exec.Command("/sbin/route", append([]string{"-n", "get"}, args...)...).CombinedOutput()
		return string(out)
	}
	if out := show("198.51.100.9"); !strings.Contains(out, "interface: lo0") {
		t.Fatalf("IPv4 route not installed:\n%s", out)
	}
	if out := show("-inet6", "2001:db8:77::9"); !strings.Contains(out, "interface: lo0") {
		t.Fatalf("IPv6 route not installed:\n%s", out)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if out := show("198.51.100.9"); strings.Contains(out, "destination: 198.51.100.0") {
		t.Fatalf("route not removed:\n%s", out)
	}
}
