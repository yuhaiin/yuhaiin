package forward

import (
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Live PF test for a Mac: loads real rules into the Yuhaiin anchor, checks
// them and the sysctl, and verifies Close restores everything. It changes
// PF state, so it runs only with YUHAIIN_TEST_DARWIN_LIVE=1 as root
// (scripts/integration/system-network-macos.sh --live).
func TestDarwinLivePF(t *testing.T) {
	if os.Getenv("YUHAIIN_TEST_DARWIN_LIVE") != "1" || os.Geteuid() != 0 {
		t.Skip("set YUHAIIN_TEST_DARWIN_LIVE=1 and run as root")
	}
	before, _ := exec.Command("/usr/sbin/sysctl", "-n", darwinSysctlIPv4).Output()
	m := New()
	plan := Plan{IPv4: true, IPv6: true, Rules: []Rule{
		{ID: "lan", Ingress: "lo0", Sources: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8:20::/64")},
			Destinations: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
			Egress:       Egress{Name: "lo0", Link: 1, Gateway: netip.MustParseAddr("127.0.0.1"), GatewayV6: netip.MustParseAddr("::1")}, Masquerade: true},
		{ID: "rest", Ingress: "lo0", Egress: Egress{Routes: true}},
	}}
	if err := m.Apply(plan); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	rules, err := exec.Command("/sbin/pfctl", "-a", PFAnchor, "-s", "rules").CombinedOutput()
	if err != nil || !strings.Contains(string(rules), "route-to") || !strings.Contains(string(rules), "block") {
		t.Fatalf("anchor rules = %s %v", rules, err)
	}
	nat, err := exec.Command("/sbin/pfctl", "-a", PFAnchor, "-s", "nat").CombinedOutput()
	if err != nil || !strings.Contains(string(nat), "nat on lo0") {
		t.Fatalf("anchor nat = %s %v", nat, err)
	}
	if v, _ := exec.Command("/usr/sbin/sysctl", "-n", darwinSysctlIPv4).Output(); strings.TrimSpace(string(v)) != "1" {
		t.Fatalf("IPv4 forwarding = %s", v)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	rules, _ = exec.Command("/sbin/pfctl", "-a", PFAnchor, "-s", "rules").CombinedOutput()
	if strings.Contains(string(rules), "pass") {
		t.Fatalf("anchor not flushed: %s", rules)
	}
	if v, _ := exec.Command("/usr/sbin/sysctl", "-n", darwinSysctlIPv4).Output(); strings.TrimSpace(string(v)) != strings.TrimSpace(string(before)) {
		t.Fatalf("IPv4 forwarding not restored: %s, was %s", v, before)
	}
}
