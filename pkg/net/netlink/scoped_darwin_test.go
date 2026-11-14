package netlink

import (
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

type fakeRoutingTable struct {
	rib    []RIBRoute
	writes []string
}

func (f *fakeRoutingTable) write(op int, r ScopedRoute) error {
	def := defaultPrefix(r.IPv6)
	switch op {
	case unix.RTM_ADD:
		f.writes = append(f.writes, "add "+r.Gateway.String())
		f.rib = append(f.rib, RIBRoute{Dst: def, Gateway: r.Gateway, Index: r.Index, Scoped: true})
	case unix.RTM_DELETE:
		f.writes = append(f.writes, "delete "+r.Gateway.String())
		out := f.rib[:0]
		for _, e := range f.rib {
			// Like XNU: destination and scope, gateway ignored.
			if !(e.Index == r.Index && e.Scoped && e.Dst == def) {
				out = append(out, e)
			}
		}
		f.rib = out
	}
	return nil
}

func fakeManager(table *fakeRoutingTable, ifaces []ScopedInterface) *ScopedRouteManager {
	m := NewScopedRouteManager(nil)
	m.readRIB = func() ([]RIBRoute, error) { return append([]RIBRoute(nil), table.rib...), nil }
	m.interfaces = func(func(string) bool) ([]ScopedInterface, error) { return ifaces, nil }
	m.write = table.write
	return m
}

func TestScopedManagerOwnsOnlyItsRoutes(t *testing.T) {
	table := &fakeRoutingTable{rib: []RIBRoute{rib("0.0.0.0/0", "192.168.1.1", 11, false)}}
	m := fakeManager(table, []ScopedInterface{en0, en5})
	if err := m.Reconcile(); err != nil {
		t.Fatal(err)
	}
	// A VPN takes the global default.
	table.rib = []RIBRoute{rib("0.0.0.0/0", "10.8.0.1", 30, false)}
	if err := m.Reconcile(); err != nil {
		t.Fatal(err)
	}
	if strings.Join(table.writes, ",") != "add 192.168.1.1" {
		t.Fatalf("writes = %v", table.writes)
	}
	routes, _ := m.Routes()
	if got := find(routes, "en0", false); got.State != ScopedOwned {
		t.Fatalf("en0 = %+v", got)
	}
	// Reconciling again is idempotent.
	if err := m.Reconcile(); err != nil || len(table.writes) != 1 {
		t.Fatalf("second reconcile wrote %v (%v)", table.writes, err)
	}

	// Another program replaces our route: we must not delete theirs.
	for i := range table.rib {
		if table.rib[i].Index == 11 && table.rib[i].Scoped {
			table.rib[i].Gateway = netip.MustParseAddr("192.168.1.254")
		}
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if len(table.writes) != 1 {
		t.Fatalf("close touched a foreign route: %v", table.writes)
	}
}

func TestScopedManagerCloseRemovesOurs(t *testing.T) {
	table := &fakeRoutingTable{rib: []RIBRoute{rib("0.0.0.0/0", "192.168.1.1", 11, false), rib("0.0.0.0/0", "192.168.20.1", 15, true)}}
	m := fakeManager(table, []ScopedInterface{en0, en5})
	_ = m.Reconcile()
	table.rib = []RIBRoute{rib("0.0.0.0/0", "10.8.0.1", 30, false), rib("0.0.0.0/0", "192.168.20.1", 15, true)}
	_ = m.Reconcile()
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if strings.Join(table.writes, ",") != "add 192.168.1.1,delete 192.168.1.1" {
		t.Fatalf("writes = %v", table.writes)
	}
	for _, e := range table.rib {
		if e.Index == 11 {
			t.Fatalf("our route kept: %+v", e)
		}
	}
	if len(table.rib) != 2 {
		t.Fatalf("foreign routes changed: %+v", table.rib)
	}
}

// Reads this machine's routing table (read-only) and plans it.
func TestScopedManagerLiveRIBParses(t *testing.T) {
	routes, err := darwinRIB()
	if err != nil {
		t.Fatal(err)
	}
	defaults := 0
	for _, r := range routes {
		if r.Dst.Bits() == 0 {
			defaults++
		}
	}
	if defaults == 0 {
		t.Skip("no default route on this machine")
	}
	ifaces, err := darwinScopedInterfaces(nil)
	if err != nil {
		t.Fatal(err)
	}
	plan, create, _ := newScopedPlanner().plan(routes, ifaces, nil)
	for _, r := range plan {
		t.Logf("%-10s v6=%-5v %-11s gw=%v link=%v %s", r.Interface, r.IPv6, r.State, r.Gateway, r.Link, r.Reason)
	}
	if len(create) != 0 {
		// A first pass has nothing remembered, so it never creates routes.
		t.Fatalf("first pass created %v", create)
	}
}
