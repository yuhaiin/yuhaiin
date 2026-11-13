package sysnet

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/forward"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/iface"
)

type fakeRoutes struct {
	mu        sync.Mutex
	installed []netlink.SystemRoute
	conflicts map[netip.Prefix]bool
	err       error
	updates   int
	closed    bool
}

func (f *fakeRoutes) Update(r []netlink.SystemRoute) ([]netip.Prefix, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updates++
	if f.err != nil {
		return nil, f.err // previous routes stay installed
	}
	f.installed = nil
	var conflicts []netip.Prefix
	for _, route := range r {
		if f.conflicts[route.Prefix] {
			conflicts = append(conflicts, route.Prefix)
			continue
		}
		f.installed = append(f.installed, route)
	}
	return conflicts, nil
}

func (f *fakeRoutes) Close() error { f.closed = true; f.installed = nil; return nil }

// lookup returns the link and gateway the installed routes send addr to,
// using longest-prefix match like the kernel.
func (f *fakeRoutes) lookup(addr string) (int, netip.Addr) {
	a := netip.MustParseAddr(addr)
	best, link, gw := -1, 0, netip.Addr{}
	for _, r := range f.installed {
		if r.Prefix.Contains(a) && r.Prefix.Bits() > best {
			best, link, gw = r.Prefix.Bits(), r.Link, r.Gateway
		}
	}
	return link, gw
}

type fakeForward struct {
	plans []forward.Plan
	err   error
}

func (f *fakeForward) Apply(p forward.Plan) error { f.plans = append(f.plans, p); return f.err }
func (f *fakeForward) Close() error               { return nil }

type memoryStore struct{ config sysnet.Config }

func (s *memoryStore) LoadSystemNetwork(context.Context) (sysnet.Config, error) { return s.config, nil }
func (s *memoryStore) SaveSystemNetwork(_ context.Context, c sysnet.Config) error {
	s.config = c
	return nil
}

type geoStub struct {
	err      error
	prefixes []netip.Prefix
}

func (g *geoStub) PrefixesByCountries([]string) ([]netip.Prefix, error) { return g.prefixes, g.err }

type testNet struct {
	ifaces []iface.Info
	routes *fakeRoutes
	fwd    *fakeForward
	geo    *geoStub
	m      *Manager
}

func pfx(s ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, v := range s {
		out = append(out, netip.MustParsePrefix(v))
	}
	return out
}

func newTestNet(t *testing.T, config sysnet.Config) *testNet {
	t.Helper()
	n := &testNet{routes: &fakeRoutes{conflicts: map[netip.Prefix]bool{}}, fwd: &fakeForward{}, geo: &geoStub{prefixes: pfx("1.0.16.0/20")}}
	n.ifaces = []iface.Info{
		{Name: "lo", Index: 1, Type: iface.TypeLoopback, Up: true, Addresses: pfx("127.0.0.1/8")},
		{Name: "eth0", Index: 2, Type: iface.TypeEthernet, Up: true, HardwareAddr: "02:00:00:00:00:02", Addresses: pfx("192.168.1.20/24"), Gateway: netip.MustParseAddr("192.168.1.1")},
		{Name: "wg0", Index: 5, Type: iface.TypeTunnel, Up: true, PointToPoint: true, Addresses: pfx("10.8.0.2/32", "fd10::2/128")},
		{Name: "tailscale0", Index: 6, Type: iface.TypeTunnel, Up: true, PointToPoint: true, Addresses: pfx("100.100.1.2/32")},
	}
	n.m = New(Options{Routes: n.routes, Forward: n.fwd, GeoIP: n.geo,
		Interfaces:   func() ([]iface.Info, error) { return slices.Clone(n.ifaces), nil },
		Capabilities: PlatformCapabilities("linux", true, true)})
	if err := n.m.SetStore(t.Context(), &memoryStore{config: config}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = n.m.Close() })
	return n
}

func tunTarget(id string) sysnet.RouteTarget {
	return sysnet.RouteTarget{Type: sysnet.TargetTunInbound, InboundID: id}
}

func ifTarget(name string) sysnet.RouteTarget {
	return sysnet.RouteTarget{Type: sysnet.TargetInterface, InterfaceName: name}
}

func rule(id string, priority int, match sysnet.RouteMatch, target sysnet.RouteTarget) sysnet.RouteRule {
	return sysnet.RouteRule{ID: id, Name: id, Enabled: true, Priority: priority, Match: match, Target: target}
}

func custom(cidrs ...string) sysnet.RouteMatch {
	return sysnet.RouteMatch{Mode: sysnet.ModeCustom, IncludeCIDRs: cidrs}
}

func ruleStatus(t *testing.T, s sysnet.Status, id string) sysnet.RuleStatus {
	t.Helper()
	for _, r := range s.Rules {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("no status for %s in %+v", id, s.Rules)
	return sysnet.RuleStatus{}
}

func (n *testNet) attach(id string, index int, v6 bool, required ...string) {
	n.m.AttachTun(TunAttachment{InboundID: id, InboundName: "TUN " + id, Interface: "utun" + id, Index: index, IPv4: true, IPv6: v6, Required: pfx(required...)})
}

func TestMultipleTargetsByPriority(t *testing.T) {
	n := newTestNet(t, sysnet.Config{Routes: []sysnet.RouteRule{
		rule("tailscale", 200, custom("100.64.0.0/10"), ifTarget("tailscale0")),
		rule("global-a", 100, sysnet.RouteMatch{Mode: sysnet.ModeNonPrivate}, tunTarget("a")),
		rule("wg", 300, custom("10.10.0.0/16", "fd10:10::/32"), ifTarget("wg0")),
		rule("dns-b", 400, custom("8.8.8.8"), tunTarget("b")),
		rule("lan-gw", 500, custom("203.0.113.0/24"), ifTarget("eth0")),
	}})
	n.attach("a", 10, true, "198.18.0.0/15")
	n.attach("b", 11, false)
	s := n.m.Status()
	if s.State != sysnet.StateActive {
		t.Fatalf("state = %s %s", s.State, s.Error)
	}
	for addr, want := range map[string]int{"1.1.1.1": 10, "2606:4700::1": 10, "100.100.1.1": 6, "10.10.1.1": 5, "fd10:10::1": 5, "198.18.0.1": 10, "192.168.1.30": 0} {
		if got, _ := n.routes.lookup(addr); got != want {
			t.Errorf("%s -> link %d, want %d", addr, got, want)
		}
	}
	// 8.8.8.8 and 203.0.113.0/24 are public: the higher-priority non-private
	// rule owns them, so the later rules are shadowed instead of competing.
	if got, _ := n.routes.lookup("8.8.8.8"); got != 10 {
		t.Fatalf("8.8.8.8 -> %d", got)
	}
	if st := ruleStatus(t, s, "dns-b"); !st.Shadowed || !slices.Equal(st.OverriddenBy, []string{"global-a"}) || st.IPv4Routes != 0 {
		t.Fatalf("dns-b = %+v", st)
	}
	if st := ruleStatus(t, s, "tailscale"); st.State != sysnet.StateActive || st.Interface != "tailscale0" || st.InterfaceIndex != 6 {
		t.Fatalf("tailscale = %+v", st)
	}
	// Required FakeIP routes win over rules and are reported separately.
	if len(s.Required) != 1 || s.Required[0].InboundID != "a" {
		t.Fatalf("required = %+v", s.Required)
	}
	// No prefix is installed twice.
	seen := map[netip.Prefix]bool{}
	for _, r := range n.routes.installed {
		if seen[r.Prefix] {
			t.Fatalf("duplicate prefix %s", r.Prefix)
		}
		seen[r.Prefix] = true
	}

	// Moving the specific rule first makes it win.
	config, _ := n.m.Config(t.Context())
	for i := range config.Routes {
		if config.Routes[i].ID == "dns-b" {
			config.Routes[i].Priority = 50
		}
	}
	if _, err := n.m.Save(t.Context(), config); err != nil {
		t.Fatal(err)
	}
	if got, _ := n.routes.lookup("8.8.8.8"); got != 11 {
		t.Fatalf("after priority change 8.8.8.8 -> %d", got)
	}
}

func TestGatewayResolution(t *testing.T) {
	n := newTestNet(t, sysnet.Config{Routes: []sysnet.RouteRule{rule("lan", 100, custom("203.0.113.0/24", "2001:db8:5::/48"), ifTarget("eth0"))}})
	st := ruleStatus(t, n.m.Status(), "lan")
	link, gw := n.routes.lookup("203.0.113.9")
	if link != 2 || gw != netip.MustParseAddr("192.168.1.1") {
		t.Fatalf("detected gateway route = %d %s", link, gw)
	}
	// eth0 has no IPv6 address: that family is dropped quietly.
	if st.State != sysnet.StateActive || st.IPv6Routes != 0 {
		t.Fatalf("status = %+v", st)
	}

	// An explicit gateway outside the interface's network is refused.
	config, _ := n.m.Config(t.Context())
	config.Routes[0].Target.Gateway = "10.0.0.1"
	if _, err := n.m.Save(t.Context(), config); err != nil {
		t.Fatal(err)
	}
	if st := ruleStatus(t, n.m.Status(), "lan"); st.State != sysnet.StateFailed || st.Error == "" {
		t.Fatalf("off-link gateway accepted: %+v", st)
	}
	// No gateway detected and none configured: a clear error, no routes.
	n.ifaces[1].Gateway = netip.Addr{}
	config.Routes[0].Target.Gateway = ""
	if _, err := n.m.Save(t.Context(), config); err != nil {
		t.Fatal(err)
	}
	st = ruleStatus(t, n.m.Status(), "lan")
	if st.State != sysnet.StateFailed || link0(n.routes, "203.0.113.9") {
		t.Fatalf("missing gateway = %+v", st)
	}
	config.Routes[0].Target.Gateway = "192.168.1.254"
	if _, err := n.m.Save(t.Context(), config); err != nil {
		t.Fatal(err)
	}
	if _, gw := n.routes.lookup("203.0.113.9"); gw != netip.MustParseAddr("192.168.1.254") {
		t.Fatalf("explicit gateway = %s", gw)
	}
}

func link0(f *fakeRoutes, addr string) bool { l, _ := f.lookup(addr); return l != 0 }

func TestUnavailableTargetsAndReconciliation(t *testing.T) {
	n := newTestNet(t, sysnet.Config{Routes: []sysnet.RouteRule{
		rule("wg", 100, custom("10.10.0.0/16"), ifTarget("wg0")),
		rule("tun", 200, custom("10.0.0.0/8"), tunTarget("a")),
	}})
	if st := ruleStatus(t, n.m.Status(), "tun"); st.State != sysnet.StateUnavailable {
		t.Fatalf("stopped TUN = %+v", st)
	}
	n.attach("a", 10, false)
	if got, _ := n.routes.lookup("10.20.0.1"); got != 10 {
		t.Fatal("TUN start did not install its rule")
	}
	// wg0 disappears: its rule becomes unavailable and its range falls
	// through to the next rule.
	wg := n.ifaces[2]
	n.ifaces = slices.Delete(n.ifaces, 2, 3)
	n.m.mu.Lock()
	n.m.reconcileLocked("test")
	n.m.mu.Unlock()
	if st := ruleStatus(t, n.m.Status(), "wg"); st.State != sysnet.StateUnavailable {
		t.Fatalf("missing interface = %+v", st)
	}
	if got, _ := n.routes.lookup("10.10.1.1"); got != 10 {
		t.Fatalf("fallthrough -> %d", got)
	}
	list, err := n.m.Interfaces(t.Context())
	if err != nil || len(list.Missing) != 1 || list.Missing[0].Target.InterfaceName != "wg0" || list.Missing[0].RuleIDs[0] != "wg" {
		t.Fatalf("missing targets = %+v %v", list.Missing, err)
	}
	// It comes back with a new index after a rename: found by hardware address.
	wg.Index, wg.Name, wg.HardwareAddr = 15, "wg1", "aa:bb:cc:00:00:01"
	n.ifaces = append(n.ifaces, wg)
	config, _ := n.m.Config(t.Context())
	config.Routes[0].Target.HardwareAddr = "aa:bb:cc:00:00:01"
	if _, err := n.m.Save(t.Context(), config); err != nil {
		t.Fatal(err)
	}
	if got, _ := n.routes.lookup("10.10.1.1"); got != 15 {
		t.Fatalf("after reappearance -> %d", got)
	}
	// TUN stops: its routes are removed before the device closes.
	n.m.DetachTun("a")
	if got, _ := n.routes.lookup("10.20.0.1"); got != 0 {
		t.Fatal("routes kept for a stopped TUN")
	}
}

func TestOwnershipViews(t *testing.T) {
	n := newTestNet(t, sysnet.Config{})
	n.attach("a", 10, false)
	n.ifaces = append(n.ifaces, iface.Info{Name: "utuna", Index: 10, Type: iface.TypeTunnel, Up: true})
	list, err := n.m.Interfaces(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	owners := map[string]string{}
	routable := map[string]bool{}
	for _, i := range list.Items {
		owners[i.Name], routable[i.Name] = i.Ownership, i.Routable
	}
	if owners["utuna"] != sysnet.OwnerYuhaiin || owners["wg0"] != sysnet.OwnerExternal || owners["eth0"] != sysnet.OwnerSystem || owners["lo"] != sysnet.OwnerSystem {
		t.Fatalf("ownership = %v", owners)
	}
	if routable["lo"] || routable["utuna"] || !routable["wg0"] || !routable["eth0"] {
		t.Fatalf("routable = %v", routable)
	}
}

func TestConflictsApplyFailureAndStaleGeoIP(t *testing.T) {
	geoRule := rule("jp", 100, sysnet.RouteMatch{Mode: sysnet.ModeCustom, GeoIPCountries: []string{"JP"}}, ifTarget("wg0"))
	n := newTestNet(t, sysnet.Config{Routes: []sysnet.RouteRule{geoRule, rule("ts", 200, custom("100.64.0.0/10"), ifTarget("wg0"))}})
	if got, _ := n.routes.lookup("1.0.16.1"); got != 5 {
		t.Fatal("GeoIP rule not applied")
	}
	// The GeoIP database goes away: the last good routes stay.
	n.geo.err = errors.New("GeoIP database is not loaded")
	n.m.mu.Lock()
	n.m.reconcileLocked("test")
	n.m.mu.Unlock()
	st := ruleStatus(t, n.m.Status(), "jp")
	if st.State != sysnet.StateDegraded || !st.Stale || st.IPv4Routes == 0 {
		t.Fatalf("stale GeoIP = %+v", st)
	}
	if got, _ := n.routes.lookup("1.0.16.1"); got != 5 {
		t.Fatal("GeoIP routes emptied while the database was missing")
	}
	// A route another program owns is reported as a conflict.
	n.geo.err = nil
	n.routes.conflicts[netip.MustParsePrefix("100.64.0.0/10")] = true
	n.m.mu.Lock()
	n.m.reconcileLocked("test")
	n.m.mu.Unlock()
	if st := ruleStatus(t, n.m.Status(), "ts"); st.State != sysnet.StateConflict || !slices.Equal(st.Conflicts, []string{"100.64.0.0/10"}) {
		t.Fatalf("conflict = %+v", st)
	}
	// The OS rejects an update: saved, reported as failed, previous routes kept.
	n.routes.err = errors.New("operation not permitted")
	before := slices.Clone(n.routes.installed)
	result, err := n.m.Save(t.Context(), sysnet.Config{Routes: []sysnet.RouteRule{rule("new", 100, custom("9.9.9.9"), ifTarget("wg0"))}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status.State != sysnet.StateFailed || ruleStatus(t, result.Status, "new").State != sysnet.StateFailed || len(result.Config.Routes) != 1 {
		t.Fatalf("apply failure = %+v", result.Status)
	}
	if !slices.Equal(n.routes.installed, before) {
		t.Fatal("previous routes not kept after a failed apply")
	}
}

func TestCapabilitiesRejectUnsupportedConfiguration(t *testing.T) {
	m := New(Options{Capabilities: PlatformCapabilities("darwin", true, false), Interfaces: func() ([]iface.Info, error) { return nil, nil }})
	if err := m.SetStore(t.Context(), &memoryStore{}); err != nil {
		t.Fatal(err)
	}
	fwd := sysnet.Config{Forwarding: sysnet.Forwarding{IPv4: true}}
	if _, err := m.Save(t.Context(), fwd); err == nil {
		t.Fatal("macOS accepted forwarding")
	}
	tproxy := sysnet.Config{Routes: []sysnet.RouteRule{rule("x", 1, custom("1.1.1.1"), sysnet.RouteTarget{Type: sysnet.TargetTProxy, InboundID: "t"})}}
	if _, err := m.Save(t.Context(), tproxy); err == nil {
		t.Fatal("TProxy accepted as a route target")
	}
	android := PlatformCapabilities("android", false, false)
	if android.MultipleTargets || android.ExternalInterfaces || android.IPv4Forwarding || !slices.Equal(android.RouteTargets, []string{sysnet.TargetTunInbound}) {
		t.Fatalf("android capabilities = %+v", android)
	}
	linux := PlatformCapabilities("linux", true, true)
	if !linux.PolicyRouting || !linux.TProxy || !linux.NAT || !slices.Contains(linux.ForwardTargets, sysnet.TargetTProxy) {
		t.Fatalf("linux capabilities = %+v", linux)
	}
}

func TestForwardingPlan(t *testing.T) {
	n := newTestNet(t, sysnet.Config{})
	n.attach("a", 10, true)
	n.m.SetInbounds(inboundsStub{tproxy: []sysnet.TProxyInbound{{ID: "tp", Listen: "0.0.0.0:7893"}}})
	config := sysnet.Config{Forwarding: sysnet.Forwarding{IPv4: true, Rules: []sysnet.ForwardRule{
		{ID: "lan", Enabled: true, IngressInterface: "eth0", SourceCIDRs: []string{"192.168.1.0/24"}, Egress: tunTarget("a"), Masquerade: true},
		{ID: "tp", Enabled: true, IngressInterface: "eth0", SourceCIDRs: []string{"192.168.1.50"}, Egress: sysnet.RouteTarget{Type: sysnet.TargetTProxy, InboundID: "tp"}},
		{ID: "gone", Enabled: true, IngressInterface: "eth9", SourceCIDRs: []string{"192.168.9.0/24"}, Egress: tunTarget("a")},
	}}}
	result, err := n.m.Save(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	plan := n.fwd.plans[len(n.fwd.plans)-1]
	if !plan.IPv4 || plan.IPv6 || len(plan.Rules) != 2 {
		t.Fatalf("plan = %+v", plan)
	}
	if plan.Rules[0].Egress.Link != 10 || !plan.Rules[0].Masquerade || plan.Rules[1].Egress.TProxyPort != 7893 {
		t.Fatalf("resolved rules = %+v", plan.Rules)
	}
	fs := result.Status.Forwarding
	if fs.State != sysnet.StateActive || fs.Rules[2].State != sysnet.StateUnavailable || fs.Rules[0].State != sysnet.StateActive {
		t.Fatalf("forwarding status = %+v", fs)
	}
	// An applier failure is reported, not hidden.
	n.fwd.err = errors.New("nftables unavailable")
	result, _ = n.m.Save(t.Context(), config)
	if result.Status.Forwarding.State != sysnet.StateFailed || result.Status.State != sysnet.StateDegraded {
		t.Fatalf("failure status = %+v", result.Status)
	}
}

type inboundsStub struct {
	tun    []sysnet.TunInbound
	tproxy []sysnet.TProxyInbound
}

func (s inboundsStub) TunInbounds(context.Context) []sysnet.TunInbound       { return s.tun }
func (s inboundsStub) TProxyInbounds(context.Context) []sysnet.TProxyInbound { return s.tproxy }

func TestPreviewShowsPriorityAndShadowing(t *testing.T) {
	n := newTestNet(t, sysnet.Config{})
	preview := n.m.Preview(t.Context(), sysnet.Config{Routes: []sysnet.RouteRule{
		rule("global", 100, sysnet.RouteMatch{Mode: sysnet.ModeGlobal}, tunTarget("a")),
		rule("dns", 200, custom("8.8.8.8"), tunTarget("b")),
		rule("off", 300, custom("9.9.9.9"), tunTarget("b")),
	}})
	if preview.Error != "" || len(preview.Rules) != 3 {
		t.Fatalf("preview = %+v", preview)
	}
	if !preview.Rules[1].Shadowed || preview.Rules[1].OverriddenBy[0] != "global" || preview.Rules[0].IPv4Routes == 0 || len(preview.Rules[0].Sample) == 0 {
		t.Fatalf("preview rules = %+v", preview.Rules)
	}
	bad := n.m.Preview(t.Context(), sysnet.Config{Routes: []sysnet.RouteRule{rule("x", 1, custom("10.0.0.0/33"), tunTarget("a"))}})
	if bad.Error == "" {
		t.Fatal("invalid CIDR previewed")
	}
}

func TestDisabledRulesAndRepeatedSaves(t *testing.T) {
	r := rule("a", 100, custom("10.0.0.0/8"), tunTarget("a"))
	n := newTestNet(t, sysnet.Config{Routes: []sysnet.RouteRule{r}})
	n.attach("a", 10, false)
	for range 3 {
		if _, err := n.m.Save(t.Context(), sysnet.Config{Routes: []sysnet.RouteRule{r}}); err != nil {
			t.Fatal(err)
		}
	}
	if len(n.routes.installed) != 1 {
		t.Fatalf("repeated saves installed %v", n.routes.installed)
	}
	r.Enabled = false
	if _, err := n.m.Save(t.Context(), sysnet.Config{Routes: []sysnet.RouteRule{r}}); err != nil {
		t.Fatal(err)
	}
	if st := ruleStatus(t, n.m.Status(), "a"); st.State != sysnet.StateDisabled || len(n.routes.installed) != 0 {
		t.Fatalf("disabled = %+v %v", st, n.routes.installed)
	}
	if err := n.m.Close(); err != nil || !n.routes.closed {
		t.Fatal("close did not clean up")
	}
}

func TestConcurrentTunStartStop(t *testing.T) {
	n := newTestNet(t, sysnet.Config{Routes: []sysnet.RouteRule{
		rule("a", 100, custom("10.1.0.0/16"), tunTarget("a")),
		rule("b", 200, custom("10.2.0.0/16"), tunTarget("b")),
	}})
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Go(func() {
			id := []string{"a", "b"}[i%2]
			n.attach(id, 10+i%2, false)
			if i%4 < 2 {
				n.m.DetachTun(id)
			}
			n.m.Reconcile("concurrent")
		})
	}
	wg.Wait()
	n.attach("a", 10, false)
	n.attach("b", 11, false)
	if a, _ := n.routes.lookup("10.1.0.1"); a != 10 {
		t.Fatal("TUN A routes missing")
	}
	if b, _ := n.routes.lookup("10.2.0.1"); b != 11 {
		t.Fatal("TUN B routes missing")
	}
}

func TestMonitorReconcilesInterfaceChanges(t *testing.T) {
	n := newTestNet(t, sysnet.Config{Routes: []sysnet.RouteRule{rule("wg", 100, custom("10.10.0.0/16"), ifTarget("wg0"))}})
	var mu sync.Mutex
	list := slices.Clone(n.ifaces)
	n.m.opts.Interfaces = func() ([]iface.Info, error) { mu.Lock(); defer mu.Unlock(); return slices.Clone(list), nil }
	n.m.startMonitor(10 * time.Millisecond)
	mu.Lock()
	list = slices.DeleteFunc(list, func(i iface.Info) bool { return i.Name == "wg0" })
	mu.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	for ruleStatus(t, n.m.Status(), "wg").State != sysnet.StateUnavailable {
		if time.Now().After(deadline) {
			t.Fatal("interface removal not reconciled")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
