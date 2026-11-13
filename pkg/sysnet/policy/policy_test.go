package policy

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
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

func generate(t *testing.T, routing sysnet.RouteMatch, geo GeoIPSource) (*netipx.IPSet, []netip.Prefix) {
	t.Helper()
	routes, err := RuleRoutes(routing, geo)
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
	set, routes := generate(t, sysnet.RouteMatch{Mode: sysnet.ModeGlobal}, nil)
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
	set, _ := generate(t, sysnet.RouteMatch{Mode: sysnet.ModeNonPrivate}, nil)
	expectRouted(t, set, true, "1.1.1.1", "8.8.8.8", "198.18.0.1", "100.63.255.255", "100.128.0.0", "172.32.0.1",
		"2001:4860::8888", "64:ff9b::808:808")
	expectRouted(t, set, false,
		"10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.0.1", "127.0.0.1", "169.254.169.254",
		// Tailscale CGNAT range and Tailscale/IPv6 ULA.
		"100.64.0.1", "100.100.100.100", "100.127.255.255", "fd7a:115c:a1e0::1", "fc00::1",
		"::1", "::", "fe80::1", "ff02::1", "240.0.0.1", "224.0.0.1")
	if _, routes := generate(t, sysnet.RouteMatch{Mode: sysnet.ModeNonPrivate}, nil); len(routes) > 96 {
		t.Fatalf("non-private mode produced %d routes", len(routes))
	}
}

func TestGenerateAdditionalIncludeAndBypass(t *testing.T) {
	routing := sysnet.RouteMatch{Mode: sysnet.ModeNonPrivate,
		// A Tailscale subnet router behind a private range routed via the TUN...
		IncludeCIDRs: []string{"10.20.0.0/16", "fd00:1::/64"},
		// ...and a public subnet advertised by a subnet router kept off the TUN.
		BypassCIDRs: []string{"203.0.114.0/24", "2001:db9::/32", "10.20.30.0/24"}}
	set, _ := generate(t, routing, nil)
	expectRouted(t, set, true, "10.20.1.1", "fd00:1::1", "8.8.8.8")
	// Bypass wins over include, include wins over built-in exclusions.
	expectRouted(t, set, false, "10.20.30.1", "203.0.114.5", "2001:db9::1", "10.21.0.1", "fd00:2::1")
	// Loopback can never be included.
	set, _ = generate(t, sysnet.RouteMatch{Mode: sysnet.ModeNonPrivate, IncludeCIDRs: []string{"127.0.0.0/8", "224.0.0.0/4"}}, nil)
	expectRouted(t, set, false, "127.0.0.1")
	expectRouted(t, set, true, "224.0.0.251")
	// Global uses only bypass; fields of other modes are kept but ignored.
	set, _ = generate(t, sysnet.RouteMatch{Mode: sysnet.ModeGlobal, IncludeCIDRs: []string{"224.0.0.0/4"},
		BypassCIDRs: []string{"8.8.8.0/24"}, GeoIPCountries: []string{"JP"}, GeoIPInvert: true}, nil)
	expectRouted(t, set, false, "224.0.0.251", "8.8.8.8")
	expectRouted(t, set, true, "1.1.1.1")
}

func TestGenerateCustomCIDRRoutes(t *testing.T) {
	set, routes := generate(t, sysnet.RouteMatch{Mode: sysnet.ModeCustom,
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
	_, routes := generate(t, sysnet.RouteMatch{Mode: sysnet.ModeCustom,
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
	set, routes := generate(t, sysnet.RouteMatch{Mode: sysnet.ModeCustom, GeoIPCountries: []string{"jp", "US", "JP"}}, geo)
	expectRouted(t, set, true, "1.0.16.1", "3.1.2.3", "2001:200::1", "2600::1")
	expectRouted(t, set, false, "8.8.8.8", "10.0.0.1", "2a00::1")
	// Adjacent country prefixes are merged.
	if !slices.Contains(routes, netip.MustParsePrefix("3.0.0.0/8")) {
		t.Fatalf("adjacent prefixes were not merged: %v", routes)
	}

	set, _ = generate(t, sysnet.RouteMatch{Mode: sysnet.ModeCustom, GeoIPCountries: []string{"JP", "US"}, GeoIPInvert: true,
		BypassCIDRs: []string{"9.9.9.9"}}, geo)
	expectRouted(t, set, true, "8.8.8.8", "2a00::1", "1.0.15.255", "1.0.32.0")
	// Reverse excludes the countries, private networks and explicit bypasses.
	expectRouted(t, set, false, "1.0.16.1", "3.1.2.3", "2001:200::1", "2600::1", "10.0.0.1", "192.168.1.1", "100.64.0.1", "fd00::1", "9.9.9.9", "127.0.0.1")

	if _, err := RuleRoutes(sysnet.RouteMatch{Mode: sysnet.ModeCustom, GeoIPCountries: []string{"JP"}}, nil); !errors.Is(err, ErrGeoIPUnavailable) {
		t.Fatalf("missing GeoIP database error = %v", err)
	}
	geo.err = errors.New("database closed")
	if _, err := RuleRoutes(sysnet.RouteMatch{Mode: sysnet.ModeCustom, GeoIPCountries: []string{"JP"}}, geo); err == nil {
		t.Fatal("GeoIP lookup error was ignored")
	}
}

func TestGenerateGeoIPFromMaxMindDB(t *testing.T) {
	db, err := maxminddb.NewMaxMindDB("../../net/trie/maxminddb/testdata/countries.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	_, routes := generate(t, sysnet.RouteMatch{Mode: sysnet.ModeCustom, GeoIPCountries: []string{"CN", "JP"}}, db)
	want := mustPrefixes("1.0.0.0/23", "2001:4860::/48")
	if !slices.Equal(routes, want) {
		t.Fatalf("routes = %v, want %v", routes, want)
	}
	set, _ := generate(t, sysnet.RouteMatch{Mode: sysnet.ModeCustom, GeoIPCountries: []string{"CN"}, GeoIPInvert: true}, db)
	expectRouted(t, set, false, "1.0.0.1", "1.0.1.255")
	expectRouted(t, set, true, "1.0.2.0", "2001:4860::1", "2.0.0.1")
}

func TestGenerateInvalidRouting(t *testing.T) {
	for name, routing := range map[string]sysnet.RouteMatch{
		"invalid cidr":        {Mode: sysnet.ModeCustom, IncludeCIDRs: []string{"10.0.0.0/33"}},
		"garbage cidr":        {Mode: sysnet.ModeNonPrivate, BypassCIDRs: []string{"not-a-cidr"}},
		"empty cidr":          {Mode: sysnet.ModeGlobal, IncludeCIDRs: []string{" "}},
		"zone":                {Mode: sysnet.ModeCustom, IncludeCIDRs: []string{"fe80::1%eth0"}},
		"file source":         {Mode: sysnet.ModeCustom, IncludeCIDRs: []string{"file:/etc/routes"}},
		"unknown mode":        {Mode: "everything"},
		"empty custom":        {Mode: sysnet.ModeCustom},
		"bad country":         {Mode: sysnet.ModeCustom, GeoIPCountries: []string{"J P"}},
		"hidden invalid cidr": {Mode: sysnet.ModeGlobal, IncludeCIDRs: []string{"10.0.0.0/8", "bad"}},
		"hidden bad country":  {Mode: sysnet.ModeNonPrivate, GeoIPCountries: []string{"J/P"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := RuleRoutes(routing, &geoIPStub{}); err == nil {
				t.Fatal("invalid routing accepted")
			}
			rule := sysnet.RouteRule{ID: "r", Match: routing, Target: sysnet.RouteTarget{Type: sysnet.TargetInterface, InterfaceName: "wg0"}}
			if err := (sysnet.Config{Routes: []sysnet.RouteRule{rule}}).Validate(); err == nil {
				t.Fatal("config validation accepted invalid routing")
			}
		})
	}
	_, err := RuleRoutes(sysnet.RouteMatch{Mode: sysnet.ModeCustom, IncludeCIDRs: []string{"1.1.1.1", "10.0.0.0/33"}}, nil)
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
	_, err := RuleRoutes(sysnet.RouteMatch{Mode: sysnet.ModeCustom, GeoIPCountries: []string{"XX"}}, geo)
	if err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("route limit not enforced: %v", err)
	}
}

func candidate(t *testing.T, id string, prefixes ...string) Candidate {
	t.Helper()
	return Candidate{ID: id, Set: SetOf(mustPrefixes(prefixes...))}
}

func TestResolveFirstMatchByPriority(t *testing.T) {
	// Evaluation order is priority order: a broad rule before a narrow one
	// owns the overlap, unlike the OS's longest-prefix match.
	got, err := Resolve([]Candidate{
		candidate(t, "global-tun-a", "0.0.0.0/1", "128.0.0.0/1", "::/1"),
		candidate(t, "tailscale", "100.64.0.0/10"),
		candidate(t, "wg", "10.10.0.0/16", "fd00:10::/32"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !got[1].Shadowed || len(got[1].Set.Prefixes()) != 0 || !slices.Equal(got[1].OverriddenBy, []string{"global-tun-a"}) {
		t.Fatalf("fully overlapped rule not shadowed: %+v", got[1])
	}
	if got[2].Shadowed || !slices.Equal(got[2].Set.Prefixes(), mustPrefixes("fd00:10::/32")) || !slices.Equal(got[2].OverriddenBy, []string{"global-tun-a"}) {
		t.Fatalf("partly overlapped rule = %v %+v", got[2].Set.Prefixes(), got[2])
	}

	// Specific rules first, then the catch-all minus what they own.
	got, err = Resolve([]Candidate{
		candidate(t, "tailscale", "100.64.0.0/10"),
		candidate(t, "dns", "8.8.8.8/32"),
		candidate(t, "global", "0.0.0.0/1", "128.0.0.0/1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	global := got[2].Set
	if global.Contains(netip.MustParseAddr("100.100.100.100")) || global.Contains(netip.MustParseAddr("8.8.8.8")) || !global.Contains(netip.MustParseAddr("8.8.4.4")) {
		t.Fatalf("catch-all kept destinations owned by earlier rules: %v", global.Prefixes())
	}
	if !slices.Equal(got[2].OverriddenBy, []string{"tailscale", "dns"}) || got[2].Shadowed {
		t.Fatalf("catch-all overrides = %+v", got[2])
	}
	// No prefix is assigned twice.
	var all netipx.IPSetBuilder
	total := 0
	for _, a := range got {
		for _, r := range a.Set.Ranges() {
			all.AddRange(r)
		}
		total += len(a.Set.Prefixes())
	}
	union, _ := all.IPSet()
	if len(union.Prefixes()) > total {
		t.Fatal("assignments overlap")
	}
}

func TestResolveDuplicateAndNilCandidates(t *testing.T) {
	got, err := Resolve([]Candidate{
		candidate(t, "a", "192.0.2.0/24"),
		{ID: "unavailable"},
		candidate(t, "b", "192.0.2.0/24"),
		candidate(t, "c", "192.0.2.0/25", "198.51.100.0/24"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got[1].Set != nil || got[1].Shadowed {
		t.Fatalf("nil candidate = %+v", got[1])
	}
	if !got[2].Shadowed || !slices.Equal(got[3].Set.Prefixes(), mustPrefixes("198.51.100.0/24")) {
		t.Fatalf("duplicates = %+v %+v", got[2], got[3])
	}
	if got[3].Shadowed || !slices.Equal(got[3].OverriddenBy, []string{"a", "b"}) {
		t.Fatalf("partial duplicate = %+v", got[3])
	}
}

func TestRoutesSplitsDefaultRoute(t *testing.T) {
	got := Routes(SetOf(mustPrefixes("0.0.0.0/0", "::/0")))
	want := mustPrefixes("0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1")
	if !slices.Equal(got, want) {
		t.Fatalf("routes = %v", got)
	}
	if v4, v6 := Families(got); v4 != 2 || v6 != 2 {
		t.Fatalf("families = %d %d", v4, v6)
	}
}
