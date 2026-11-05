package interfaces

import (
	"net/netip"
	"testing"
)

func isolateRouteSnapshot(tb testing.TB) {
	tb.Helper()
	defaultInterfaceNameMu.Lock()
	previous, trie := lastPublishedRoutes, defaultrouter.Load()
	lastPublishedRoutes = nil
	defaultrouter.Store(nil)
	tb.Cleanup(func() {
		lastPublishedRoutes = previous
		defaultrouter.Store(trie)
		defaultInterfaceNameMu.Unlock()
	})
}

func TestRouteSnapshotKeepsLatestMetadata(t *testing.T) {
	isolateRouteSnapshot(t)
	initial := router{v4: []rtInfo{{Dst: netip.MustParsePrefix("0.0.0.0/0"), OutputIface: "en0", Gateway: netip.MustParseAddr("192.0.2.1")}}}
	updateDefaultRouter(initial)
	trie := defaultrouter.Load()
	next := router{v4: append([]rtInfo(nil), initial.v4...)}
	next.v4[0].Gateway = netip.MustParseAddr("192.0.2.254")
	updateDefaultRouter(next)
	if defaultrouter.Load() != trie {
		t.Fatal("gateway-only update rebuilt the route trie")
	}
	if !lastPublishedRoutes.equal(next) {
		t.Fatal("latest route metadata was discarded; future identical polls will allocate comparison maps")
	}
	if allocs := testing.AllocsPerRun(10, func() { updateDefaultRouter(next) }); allocs != 0 {
		t.Fatalf("stable route snapshot allocated %g times per poll", allocs)
	}
	next = router{v4: append([]rtInfo(nil), next.v4...)}
	next.v4[0].OutputIface = "en1"
	updateDefaultRouter(next)
	if defaultrouter.Load() == trie {
		t.Fatal("interface update failed to publish a new trie")
	}
	if got, _ := defaultrouter.Load().Search("203.0.113.1"); got != "en1" {
		t.Fatalf("new route interface = %q", got)
	}
}

func BenchmarkRouteSnapshotAfterGatewayChange(b *testing.B) {
	isolateRouteSnapshot(b)
	initial := router{v4: make([]rtInfo, 512)}
	for i := range initial.v4 {
		initial.v4[i] = rtInfo{Dst: netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}), 24), OutputIface: "en0"}
	}
	initial.v4[0].Gateway = netip.MustParseAddr("192.0.2.1")
	updateDefaultRouter(initial)
	next := router{v4: append([]rtInfo(nil), initial.v4...)}
	next.v4[0].Gateway = netip.MustParseAddr("192.0.2.254")
	updateDefaultRouter(next)
	b.ReportAllocs()
	for b.Loop() {
		updateDefaultRouter(next)
	}
}

func BenchmarkRouterToTrie(b *testing.B) {
	routes := router{v4: make([]rtInfo, 512)}
	for i := range routes.v4 {
		routes.v4[i] = rtInfo{Dst: netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}), 24), OutputIface: "en0"}
	}
	b.ReportAllocs()
	for b.Loop() {
		routes.ToTrie()
	}
}
