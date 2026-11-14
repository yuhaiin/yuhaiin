//go:build linux && !android

package netlink

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func rulesAt(t *testing.T, f, priority int) []netlink.Rule {
	t.Helper()
	rules, err := netlink.RuleList(f)
	if err != nil {
		t.Fatal(err)
	}
	var out []netlink.Rule
	for _, r := range rules {
		if r.Priority == priority {
			out = append(out, r)
		}
	}
	return out
}

func isProtectionRule(r netlink.Rule) bool {
	return r.Table == tunRouteTable && r.Protocol == RouteProtocolYuhaiin && r.Invert &&
		r.Mark == SocketProtectionMark && r.Mask != nil && *r.Mask == 0xffffffff
}

// A rule left by a version without Socket Protection is ours and replaced; the
// new rule excludes the mark. Close removes only what this program owns.
func TestLinuxPolicyRuleMigratesUnmarkedRule(t *testing.T) {
	isolatedNamespace(t)
	tun := dummyLink(t, "yhtestm", "172.21.0.1/24")
	old := netlink.NewRule()
	old.Priority, old.Table, old.Family, old.Protocol = ruleV4, tunRouteTable, unix.AF_INET, RouteProtocolYuhaiin
	if err := netlink.RuleAdd(old); err != nil {
		t.Fatal(err)
	}
	// Another program's rule elsewhere must survive everything below.
	foreign := netlink.NewRule()
	foreign.Priority, foreign.Table, foreign.Family = 30500, 200, unix.AF_INET
	if err := netlink.RuleAdd(foreign); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netlink.RuleDel(foreign); _ = netlink.RuleDel(old) })

	m, err := NewRouteManager()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Update(via(tun, "", "0.0.0.0/1")); err != nil {
		t.Fatal(err)
	}
	got := rulesAt(t, unix.AF_INET, ruleV4)
	if len(got) != 1 || !isProtectionRule(got[0]) {
		t.Fatalf("rule at %d after migration = %+v, want one marked, inverted rule", ruleV4, got)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if got := rulesAt(t, unix.AF_INET, ruleV4); len(got) != 0 {
		t.Fatalf("owned rule kept after close: %+v", got)
	}
	if got := rulesAt(t, unix.AF_INET, 30500); len(got) != 1 {
		t.Fatalf("foreign rule touched: %+v", got)
	}
}

// Another program's rule at our priority is reported, never replaced.
func TestLinuxPolicyRuleConflict(t *testing.T) {
	isolatedNamespace(t)
	tun := dummyLink(t, "yhtestc", "172.22.0.1/24")
	foreign := netlink.NewRule()
	foreign.Priority, foreign.Table, foreign.Family = ruleV6, 100, unix.AF_INET6
	if err := netlink.RuleAdd(foreign); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netlink.RuleDel(foreign) })
	m, err := NewRouteManager()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	_, err = m.Update([]SystemRoute{{Prefix: netip.MustParsePrefix("2001:db8::/32"), Link: tun}})
	if err == nil || !strings.Contains(err.Error(), "another program") {
		t.Fatalf("update over a foreign rule: %v", err)
	}
	if got := rulesAt(t, unix.AF_INET6, ruleV6); len(got) != 1 || got[0].Table != 100 {
		t.Fatalf("foreign rule changed: %+v", got)
	}
}
