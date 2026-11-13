package inbound

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie/maxminddb"
	"go4.org/netipx"
)

type geoIPStub struct {
	prefixes map[string][]string
	err      error
	calls    int
}

func (g *geoIPStub) PrefixesByCountries(countries []string) ([]netip.Prefix, error) {
	g.calls++
	if g.err != nil {
		return nil, g.err
	}
	var out []netip.Prefix
	for _, code := range countries {
		out = append(out, mustPrefixes(g.prefixes[code]...)...)
	}
	return out, nil
}

func routeSet(t *testing.T, routes []netip.Prefix) *netipx.IPSet {
	t.Helper()
	var b netipx.IPSetBuilder
	for _, p := range routes {
		b.AddPrefix(p)
	}
	set, err := b.IPSet()
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func generate(t *testing.T, routing contract.TunRouting, geo GeoIPPrefixSource) (*netipx.IPSet, []netip.Prefix) {
	t.Helper()
	routes, err := GenerateTunRoutes(routing, geo)
	if err != nil {
		t.Fatal(err)
	}
	return routeSet(t, routes), routes
}

func expectRouted(t *testing.T, set *netipx.IPSet, routed bool, addrs ...string) {
	t.Helper()
	for _, a := range addrs {
		if got := set.Contains(netip.MustParseAddr(a)); got != routed {
			t.Errorf("%s routed = %v, want %v", a, got, routed)
		}
	}
}

func TestGenerateGlobalRoutes(t *testing.T) {
	set, routes := generate(t, contract.TunRouting{Mode: contract.TunRouteModeGlobal}, nil)
	// IPv4 and IPv6 internet traffic.
	expectRouted(t, set, true, "1.1.1.1", "8.8.8.8", "128.0.0.1", "223.255.255.255", "10.0.0.1", "192.168.1.1", "100.100.100.100",
		"2001:4860::8888", "2606:4700::1111", "fd7a:115c:a1e0::1", "8000::1")
	// Local-link, multicast, broadcast and loopback stay off the TUN.
	expectRouted(t, set, false, "127.0.0.1", "169.254.1.1", "224.0.0.251", "239.255.255.250", "255.255.255.255", "0.0.0.1",
		"::1", "::", "::ffff:1.1.1.1", "fe80::1", "ff02::fb")
	expectRouted(t, set, true, "64:ff9b::808:808")
	for _, p := range routes {
		if p.Bits() == 0 {
			t.Fatalf("default route %v would replace the system default route", p)
		}
	}
	// Exact set: aligned holes keep the route count small.
	if len(routes) > 64 {
		t.Fatalf("global mode produced %d routes", len(routes))
	}
}

func TestGenerateNonPrivateRoutes(t *testing.T) {
	set, _ := generate(t, contract.TunRouting{Mode: contract.TunRouteModeNonPrivate}, nil)
	expectRouted(t, set, true, "1.1.1.1", "8.8.8.8", "198.18.0.1", "100.63.255.255", "100.128.0.0", "172.32.0.1",
		"2001:4860::8888", "64:ff9b::808:808")
	expectRouted(t, set, false,
		"10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.0.1", "127.0.0.1", "169.254.169.254",
		// Tailscale CGNAT range and Tailscale/IPv6 ULA.
		"100.64.0.1", "100.100.100.100", "100.127.255.255", "fd7a:115c:a1e0::1", "fc00::1",
		"::1", "::", "fe80::1", "ff02::1", "240.0.0.1", "224.0.0.1")
	if _, routes := generate(t, contract.TunRouting{Mode: contract.TunRouteModeNonPrivate}, nil); len(routes) > 96 {
		t.Fatalf("non-private mode produced %d routes", len(routes))
	}
}

func TestGenerateAdditionalIncludeAndBypass(t *testing.T) {
	routing := contract.TunRouting{Mode: contract.TunRouteModeNonPrivate,
		// A Tailscale subnet router behind a private range routed via the TUN...
		IncludeCIDRs: []string{"10.20.0.0/16", "fd00:1::/64"},
		// ...and a public subnet advertised by a subnet router kept off the TUN.
		BypassCIDRs: []string{"203.0.114.0/24", "2001:db9::/32", "10.20.30.0/24"}}
	set, _ := generate(t, routing, nil)
	expectRouted(t, set, true, "10.20.1.1", "fd00:1::1", "8.8.8.8")
	// Bypass wins over include, include wins over built-in exclusions.
	expectRouted(t, set, false, "10.20.30.1", "203.0.114.5", "2001:db9::1", "10.21.0.1", "fd00:2::1")
	// Loopback can never be included.
	set, _ = generate(t, contract.TunRouting{Mode: contract.TunRouteModeNonPrivate, IncludeCIDRs: []string{"127.0.0.0/8", "224.0.0.0/4"}}, nil)
	expectRouted(t, set, false, "127.0.0.1")
	expectRouted(t, set, true, "224.0.0.251")
	// Global uses only bypass; fields of other modes are kept but ignored.
	set, _ = generate(t, contract.TunRouting{Mode: contract.TunRouteModeGlobal, IncludeCIDRs: []string{"224.0.0.0/4"},
		BypassCIDRs: []string{"8.8.8.0/24"}, GeoIPCountries: []string{"JP"}, GeoIPInvert: true}, nil)
	expectRouted(t, set, false, "224.0.0.251", "8.8.8.8")
	expectRouted(t, set, true, "1.1.1.1")
}

func TestGenerateCustomCIDRRoutes(t *testing.T) {
	set, routes := generate(t, contract.TunRouting{Mode: contract.TunRouteModeCustom,
		IncludeCIDRs: []string{"192.168.20.0/24", "10.0.0.0/8", "8.8.8.8", "2001:4860::/32", "10.1.0.0/16", " 8.8.8.8/32 "},
		BypassCIDRs:  []string{"10.9.0.0/16"}}, nil)
	expectRouted(t, set, true, "192.168.20.1", "10.0.0.1", "8.8.8.8", "2001:4860::1")
	expectRouted(t, set, false, "8.8.4.4", "192.168.21.1", "10.9.1.1", "1.1.1.1", "2001:4861::1")
	// 10/8 minus 10.9/16 is 8 prefixes; duplicates and 10.1/16 are absorbed.
	want := mustPrefixes("8.8.8.8/32", "10.0.0.0/13", "10.8.0.0/16", "10.10.0.0/15", "10.12.0.0/14", "10.16.0.0/12", "10.32.0.0/11", "10.64.0.0/10", "10.128.0.0/9", "192.168.20.0/24", "2001:4860::/32")
	if !slices.Equal(routes, want) {
		t.Fatalf("routes = %v\nwant %v", routes, want)
	}
}

func TestGeneratePrefixMergeDifferenceAndDuplicates(t *testing.T) {
	_, routes := generate(t, contract.TunRouting{Mode: contract.TunRouteModeCustom,
		IncludeCIDRs: []string{"192.0.2.0/25", "192.0.2.128/25", "192.0.2.0/24", "192.0.2.7", "198.51.100.0/24", "198.51.100.0/24"},
		BypassCIDRs:  []string{"198.51.100.128/26"}}, nil)
	want := mustPrefixes("192.0.2.0/24", "198.51.100.0/25", "198.51.100.192/26")
	if !slices.Equal(routes, want) {
		t.Fatalf("routes = %v, want %v", routes, want)
	}
}

func TestGenerateGeoIPRoutes(t *testing.T) {
	geo := &geoIPStub{prefixes: map[string][]string{
		"JP": {"1.0.16.0/20", "2001:200::/23"},
		"US": {"3.0.0.0/9", "3.128.0.0/9", "2600::/12"},
	}}
	set, routes := generate(t, contract.TunRouting{Mode: contract.TunRouteModeCustom, GeoIPCountries: []string{"jp", "US", "JP"}}, geo)
	expectRouted(t, set, true, "1.0.16.1", "3.1.2.3", "2001:200::1", "2600::1")
	expectRouted(t, set, false, "8.8.8.8", "10.0.0.1", "2a00::1")
	// Adjacent country prefixes are merged.
	if !slices.Contains(routes, netip.MustParsePrefix("3.0.0.0/8")) {
		t.Fatalf("adjacent prefixes were not merged: %v", routes)
	}

	set, _ = generate(t, contract.TunRouting{Mode: contract.TunRouteModeCustom, GeoIPCountries: []string{"JP", "US"}, GeoIPInvert: true,
		BypassCIDRs: []string{"9.9.9.9"}}, geo)
	expectRouted(t, set, true, "8.8.8.8", "2a00::1", "1.0.15.255", "1.0.32.0")
	// Reverse excludes the countries, private networks and explicit bypasses.
	expectRouted(t, set, false, "1.0.16.1", "3.1.2.3", "2001:200::1", "2600::1", "10.0.0.1", "192.168.1.1", "100.64.0.1", "fd00::1", "9.9.9.9", "127.0.0.1")

	if _, err := GenerateTunRoutes(contract.TunRouting{Mode: contract.TunRouteModeCustom, GeoIPCountries: []string{"JP"}}, nil); !errors.Is(err, ErrGeoIPUnavailable) {
		t.Fatalf("missing GeoIP database error = %v", err)
	}
	geo.err = errors.New("database closed")
	if _, err := GenerateTunRoutes(contract.TunRouting{Mode: contract.TunRouteModeCustom, GeoIPCountries: []string{"JP"}}, geo); err == nil {
		t.Fatal("GeoIP lookup error was ignored")
	}
}

func TestGenerateGeoIPFromMaxMindDB(t *testing.T) {
	db, err := maxminddb.NewMaxMindDB("../net/trie/maxminddb/testdata/countries.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	_, routes := generate(t, contract.TunRouting{Mode: contract.TunRouteModeCustom, GeoIPCountries: []string{"CN", "JP"}}, db)
	want := mustPrefixes("1.0.0.0/23", "2001:4860::/48")
	if !slices.Equal(routes, want) {
		t.Fatalf("routes = %v, want %v", routes, want)
	}
	set, _ := generate(t, contract.TunRouting{Mode: contract.TunRouteModeCustom, GeoIPCountries: []string{"CN"}, GeoIPInvert: true}, db)
	expectRouted(t, set, false, "1.0.0.1", "1.0.1.255")
	expectRouted(t, set, true, "1.0.2.0", "2001:4860::1", "2.0.0.1")
}

func TestGenerateInvalidRouting(t *testing.T) {
	for name, routing := range map[string]contract.TunRouting{
		"invalid cidr":        {Mode: contract.TunRouteModeCustom, IncludeCIDRs: []string{"10.0.0.0/33"}},
		"garbage cidr":        {Mode: contract.TunRouteModeNonPrivate, BypassCIDRs: []string{"not-a-cidr"}},
		"empty cidr":          {Mode: contract.TunRouteModeGlobal, IncludeCIDRs: []string{" "}},
		"zone":                {Mode: contract.TunRouteModeCustom, IncludeCIDRs: []string{"fe80::1%eth0"}},
		"file source":         {Mode: contract.TunRouteModeCustom, IncludeCIDRs: []string{"file:/etc/routes"}},
		"unknown mode":        {Mode: "everything"},
		"empty custom":        {Mode: contract.TunRouteModeCustom},
		"bad country":         {Mode: contract.TunRouteModeCustom, GeoIPCountries: []string{"J P"}},
		"hidden invalid cidr": {Mode: contract.TunRouteModeGlobal, IncludeCIDRs: []string{"10.0.0.0/8", "bad"}},
		"hidden bad country":  {Mode: contract.TunRouteModeNonPrivate, GeoIPCountries: []string{"J/P"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := GenerateTunRoutes(routing, &geoIPStub{}); err == nil {
				t.Fatal("invalid routing accepted")
			}
			inbound := contract.Inbound{ID: "tun", Network: contract.NewTypedNetwork(contract.EmptyNetwork{}),
				Protocol: contract.NewTypedProtocol(contract.TunProtocol{Routing: routing})}
			if err := inbound.Validate(); err == nil {
				t.Fatal("inbound validation accepted invalid routing")
			}
		})
	}
	_, err := GenerateTunRoutes(contract.TunRouting{Mode: contract.TunRouteModeCustom, IncludeCIDRs: []string{"1.1.1.1", "10.0.0.0/33"}}, nil)
	if err == nil || !strings.Contains(err.Error(), `#2 "10.0.0.0/33"`) {
		t.Fatalf("error does not identify the invalid entry: %v", err)
	}
}

func TestGenerateRouteLimit(t *testing.T) {
	// Every other /32 of a /16 cannot be merged: 32768 routes.
	var hosts []string
	for i := 0; i < 65536; i += 2 {
		hosts = append(hosts, netip.AddrFrom4([4]byte{11, 0, byte(i >> 8), byte(i)}).String()+"/32")
	}
	geo := &geoIPStub{prefixes: map[string][]string{"XX": hosts}}
	_, err := GenerateTunRoutes(contract.TunRouting{Mode: contract.TunRouteModeCustom, GeoIPCountries: []string{"XX"}}, geo)
	if err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("route limit not enforced: %v", err)
	}
}

func TestTunConfigWithRoutingIgnoresLegacyExcludes(t *testing.T) {
	legacy := contract.TunProtocol{Routes: []string{"192.0.2.0/24"}, Excludes: []string{"203.0.113.0/24"}}
	if got := tunConfig(legacy); got.ManagedRoutes || !slices.Equal(got.Routes, []string{"192.0.2.0/24", "203.0.113.0/24"}) {
		t.Fatalf("legacy routes changed: %+v", got)
	}
	in := contract.Inbound{ID: "tun", Name: "tun", Protocol: contract.NewTypedProtocol(contract.TunProtocol{
		Routes: []string{"192.0.2.0/24"}, Excludes: []string{"203.0.113.0/24"},
		Routing: contract.TunRouting{Mode: contract.TunRouteModeCustom, IncludeCIDRs: []string{"198.51.100.0/24"}}})}
	runtime, err := runtimeTun(in, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := tunConfig(*runtime.Protocol.Tun)
	if !got.ManagedRoutes || !slices.Equal(got.Routes, []string{"198.51.100.0/24"}) {
		t.Fatalf("managed routes = %+v", got)
	}
	if !slices.Equal(in.Protocol.Tun.Routes, []string{"192.0.2.0/24"}) {
		t.Fatal("runtime generation modified the stored configuration")
	}
	spec := platformSpec(*runtime.Protocol.Tun)
	if spec.RouteMode != contract.TunRouteModeCustom || len(spec.Excludes) != 0 || !slices.Equal(spec.Routes, []string{"198.51.100.0/24"}) {
		t.Fatalf("platform spec = %+v", spec)
	}
}

type routeSetterStub struct {
	routeAccepterStub
	routes  [][]netip.Prefix
	managed []bool
	err     error
}

func (s *routeSetterStub) SetRoutes(routes []netip.Prefix, managed bool) error {
	if s.closed {
		panic("route update after close")
	}
	s.routes = append(s.routes, routes)
	s.managed = append(s.managed, managed)
	return s.err
}

func tunInbound(routing contract.TunRouting) contract.Inbound {
	return contract.Inbound{ID: "tun", Name: "tun", Enabled: true, Network: contract.NewTypedNetwork(contract.EmptyNetwork{}),
		Protocol: contract.NewTypedProtocol(contract.TunProtocol{Name: "tun://utun8", Portal: "172.19.0.1/30", Routing: routing})}
}

func TestDesktopTunRouteChangesApplyInPlace(t *testing.T) {
	geo := &geoIPStub{prefixes: map[string][]string{"JP": {"1.0.16.0/20"}}}
	l := NewInbound(netapi.NewErrProxy(errors.New("test proxy")), WithGeoIPPrefixSource(geo))
	t.Cleanup(func() { _ = l.Close() })
	server := &routeSetterStub{}
	current := tunInbound(contract.TunRouting{Mode: contract.TunRouteModeGlobal})
	l.store.Store("tun", entry{contractConfig: &current, server: server})

	// Global -> Custom GeoIP keeps the same TUN.
	next := tunInbound(contract.TunRouting{Mode: contract.TunRouteModeCustom, GeoIPCountries: []string{"JP"}, IncludeCIDRs: []string{"8.8.8.8"}})
	if err := l.SaveContract(next); err != nil {
		t.Fatal(err)
	}
	if server.closed || len(server.routes) != 1 || !server.managed[0] ||
		!slices.Equal(server.routes[0], mustPrefixes("1.0.16.0/20", "8.8.8.8/32")) {
		t.Fatalf("in-place update = closed %v, %v", server.closed, server.routes)
	}
	if stored, _ := l.store.Load("tun"); stored.contractConfig.Protocol.Tun.Routing.Mode != contract.TunRouteModeCustom {
		t.Fatal("stored runtime configuration not updated")
	}

	// A GeoIP database update regenerates only GeoIP TUNs.
	geo.prefixes["JP"] = []string{"1.0.32.0/20"}
	if err := l.RefreshTunRoutes(true); err != nil {
		t.Fatal(err)
	}
	if len(server.routes) != 2 || !slices.Equal(server.routes[1], mustPrefixes("1.0.32.0/20", "8.8.8.8/32")) {
		t.Fatalf("GeoIP refresh = %v", server.routes)
	}

	// Lookup failure: the TUN keeps running, reports degraded and retries.
	geo.err = errors.New("database closed")
	if err := l.RefreshTunRoutes(true); err == nil {
		t.Fatal("GeoIP failure was swallowed")
	}
	if status := l.runtimeStatus(next); status.Status != "degraded" || !strings.Contains(status.LastError, "database closed") {
		t.Fatalf("status = %+v", status)
	}
	geo.err = nil
	if err := l.RefreshTunRoutes(false); err != nil {
		t.Fatal(err)
	}
	if status := l.runtimeStatus(next); status.Status != "running" || server.closed {
		t.Fatalf("status after network resync = %+v", status)
	}

	// Saving the same configuration again retries the route update.
	server.err = errors.New("route add failed")
	if err := l.SaveContract(next); err == nil || server.closed {
		t.Fatalf("retry error = %v, closed %v", err, server.closed)
	}
	server.err = nil

	// Non-route changes still rebuild the TUN.
	rebuilt := next
	tun := *rebuilt.Protocol.Tun
	tun.MTU = 1400
	rebuilt.Protocol.Tun = &tun
	rebuilt.Enabled = false
	if err := l.SaveContract(rebuilt); err != nil {
		t.Fatal(err)
	}
	if !server.closed {
		t.Fatal("non-route change did not rebuild the TUN")
	}
}

func TestTunRoutesOnlyChanged(t *testing.T) {
	legacy := tunInbound(contract.TunRouting{})
	legacy.Protocol.Tun.Routes = []string{"0.0.0.0/1"}
	managed := tunInbound(contract.TunRouting{Mode: contract.TunRouteModeNonPrivate, BypassCIDRs: []string{"1.1.1.1"}})
	if !tunRoutesOnlyChanged(legacy, managed) {
		t.Fatal("legacy to managed route change requires a rebuild")
	}
	if tunRoutesOnlyChanged(managed, legacy) {
		t.Fatal("managed to legacy must rebuild to restore legacy route handling")
	}
	other := managed
	tun := *other.Protocol.Tun
	tun.Portal = "172.20.0.1/30"
	other.Protocol.Tun = &tun
	if tunRoutesOnlyChanged(managed, other) {
		t.Fatal("address change treated as route-only")
	}
}

func TestPlatformTunReceivesGeneratedRoutes(t *testing.T) {
	_, provider := usePlatformStub(t)
	l := NewInbound(netapi.NewErrProxy(errors.New("test proxy")))
	t.Cleanup(func() { _ = l.Close() })
	in := platformInbound(true, 1500)
	in.Protocol.Tun.AutoFakeIPRoute = false
	in.Protocol.Tun.Routing = contract.TunRouting{Mode: contract.TunRouteModeNonPrivate, BypassCIDRs: []string{"8.8.8.0/24", "2001:4860::/32"}}
	if err := l.SaveContract(in); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { _, configs := provider.snapshot(); return len(configs) > 0 })
	_, configs := provider.snapshot()
	got := configs[len(configs)-1]
	if got.RouteMode != contract.TunRouteModeNonPrivate || len(got.Excludes) != 0 {
		t.Fatalf("platform config = %+v", got)
	}
	set := routeSet(t, mustPrefixes(got.Routes...))
	expectRouted(t, set, true, "1.1.1.1", "8.8.4.4")
	expectRouted(t, set, false, "8.8.8.8", "10.0.0.1", "100.64.0.1", "fd00::1", "2001:4860::1")

	// Switching modes reconfigures the platform interface in place.
	in.Protocol.Tun.Routing = contract.TunRouting{Mode: contract.TunRouteModeGlobal}
	if err := l.SaveContract(in); err != nil {
		t.Fatal(err)
	}
	_, configs = provider.snapshot()
	got = configs[len(configs)-1]
	if got.RouteMode != contract.TunRouteModeGlobal || !routeSet(t, mustPrefixes(got.Routes...)).Contains(netip.MustParseAddr("10.0.0.1")) {
		t.Fatalf("platform config after mode change = %+v", got)
	}
	if l.platformGeneration() == 0 {
		t.Fatal("platform TUN was not running")
	}
}

func (l *Inbound) platformGeneration() uint64 {
	entry, _ := l.store.Load("tun")
	if p, ok := entry.server.(*platformTunAccepter); ok {
		return p.Generation()
	}
	return 0
}
