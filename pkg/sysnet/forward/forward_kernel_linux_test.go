//go:build linux && !android

package forward

import (
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Runs only inside the isolated router container of
// scripts/integration/system-network-podman.sh: it changes sysctls,
// nftables and policy rules of the current network namespace.
func requireContainer(t *testing.T) {
	t.Helper()
	if os.Getenv("YUHAIIN_TEST_ISOLATED_CONTAINER") != "1" {
		t.Skip("kernel forwarding test runs only inside the Podman integration container")
	}
}

func tableNames(t *testing.T) []string {
	t.Helper()
	conn, err := nftables.New()
	if err != nil {
		t.Fatal(err)
	}
	tables, err := conn.ListTables()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, x := range tables {
		names = append(names, x.Name)
	}
	return names
}

func hasName(names []string, name string) bool {
	for _, n := range names {
		if n == name {
			return true
		}
	}
	return false
}

func ourRules(t *testing.T, f int) []netlink.Rule {
	t.Helper()
	rules, err := netlink.RuleList(f)
	if err != nil {
		t.Fatal(err)
	}
	var out []netlink.Rule
	for _, r := range rules {
		if r.Protocol == protocol {
			out = append(out, r)
		}
	}
	return out
}

func TestKernelForwardingLifecycle(t *testing.T) {
	requireContainer(t)
	root := "/proc/sys"
	if err := os.WriteFile(root+"/net/ipv4/ip_forward", []byte("0"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Another program's firewall table must survive every operation.
	conn, err := nftables.New()
	if err != nil {
		t.Fatal(err)
	}
	conn.AddTable(&nftables.Table{Name: "other_app_test", Family: nftables.TableFamilyINet})
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		conn.DelTable(&nftables.Table{Name: "other_app_test", Family: nftables.TableFamilyINet})
		_ = conn.Flush()
	})
	// A stale owned rule from a crashed run is removed on first use.
	stale := IPRule{Priority: 29500, Table: 6400, Src: netip.MustParsePrefix("192.0.2.0/24")}.netlink()
	if err := netlink.RuleAdd(stale); err != nil {
		t.Fatal(err)
	}

	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	m := New()
	plan := Plan{IPv4: true, Rules: []Rule{
		{ID: "lan", Ingress: "lo", Sources: []netip.Prefix{netip.MustParsePrefix("10.99.0.0/24")}, Egress: Egress{Name: "lo", Link: lo.Attrs().Index}, Masquerade: true},
		{ID: "tp", Ingress: "lo", Sources: []netip.Prefix{netip.MustParsePrefix("10.98.0.0/24")}, Egress: Egress{TProxyPort: 7893}},
	}}
	if err := m.Apply(plan); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(root + "/net/ipv4/ip_forward"); strings.TrimSpace(string(data)) != "1" {
		t.Fatal("IPv4 forwarding not enabled")
	}
	names := tableNames(t)
	if !hasName(names, NFTTable) || !hasName(names, "other_app_test") {
		t.Fatalf("tables = %v", names)
	}
	rules := ourRules(t, unix.AF_INET)
	if len(rules) != 2 {
		t.Fatalf("owned rules = %+v (stale rule not removed or rules missing)", rules)
	}
	routes, err := netlink.RouteListFiltered(unix.AF_INET, &netlink.Route{Table: FirstTable}, netlink.RT_FILTER_TABLE)
	if err != nil || len(routes) != 2 {
		t.Fatalf("forwarding table routes = %+v, %v", routes, err)
	}

	// Applying again is idempotent; dropping a rule removes only its state.
	if err := m.Apply(plan); err != nil {
		t.Fatal(err)
	}
	plan.Rules = plan.Rules[:1]
	if err := m.Apply(plan); err != nil {
		t.Fatal(err)
	}
	if rules := ourRules(t, unix.AF_INET); len(rules) != 1 || rules[0].Table != FirstTable {
		t.Fatalf("rules after removing TProxy = %+v", rules)
	}

	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	names = tableNames(t)
	if hasName(names, NFTTable) || !hasName(names, "other_app_test") {
		t.Fatalf("tables after close = %v", names)
	}
	if rules := ourRules(t, unix.AF_INET); len(rules) != 0 {
		t.Fatalf("rules after close = %+v", rules)
	}
	if data, _ := os.ReadFile(root + "/net/ipv4/ip_forward"); strings.TrimSpace(string(data)) != "0" {
		t.Fatal("IPv4 forwarding not restored")
	}
}
