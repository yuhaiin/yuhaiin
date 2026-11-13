package inbound

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"testing"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	contractsysnet "github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/platformvpn"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/iface"
)

type sysnetStub struct {
	mu       sync.Mutex
	attached map[string]sysnet.TunAttachment
	events   []string
}

func (s *sysnetStub) AttachTun(a sysnet.TunAttachment) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.attached == nil {
		s.attached = map[string]sysnet.TunAttachment{}
	}
	s.attached[a.InboundID] = a
	s.events = append(s.events, "attach "+a.InboundID)
}

func (s *sysnetStub) DetachTun(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.attached, id)
	s.events = append(s.events, "detach "+id)
}

func (s *sysnetStub) PlatformRoutes(string, bool, bool) ([]netip.Prefix, bool) { return nil, false }

type linkedServer struct {
	netapi.EmptyInterface
	link   tun.Link
	closed bool
	events *[]string
}

func (s *linkedServer) TunLink() tun.Link { return s.link }
func (s *linkedServer) Close() error {
	s.closed = true
	*s.events = append(*s.events, "close")
	return nil
}

func TestDesktopTunAttachesToSystemNetwork(t *testing.T) {
	stub := &sysnetStub{}
	l := NewInbound(netapi.NewErrProxy(errors.New("test proxy")), WithSystemNetwork(stub))
	t.Cleanup(func() { _ = l.Close() })
	l.fakeIPRanges = [2]netip.Prefix{netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("fc00::/18")}
	server := &linkedServer{events: &stub.events, link: tun.Link{Name: "utun8", Index: 9, IPv4: netip.MustParsePrefix("172.19.0.1/30"),
		RequiredRoutes: []netip.Prefix{netip.MustParsePrefix("172.19.0.0/30")}}}
	config := contract.Inbound{ID: "tun", Name: "TUN A", Enabled: true, Protocol: contract.NewTypedProtocol(contract.TunProtocol{AutoFakeIPRoute: true})}

	l.mu.Lock()
	l.attachTun("tun", config, server)
	l.mu.Unlock()
	l.store.Store("tun", entry{contractConfig: &config, server: server})
	a := stub.attached["tun"]
	if a.Interface != "utun8" || a.Index != 9 || !a.IPv4 || a.InboundName != "TUN A" || a.Platform != nil {
		t.Fatalf("attachment = %+v", a)
	}
	if !slices.Contains(a.Required, netip.MustParsePrefix("172.19.0.0/30")) || !slices.Contains(a.Required, netip.MustParsePrefix("198.18.0.0/15")) {
		t.Fatalf("required routes = %v", a.Required)
	}

	// A FakeIP pool change updates the required routes, not the device.
	if err := l.UpdateFakeIPRanges([2]netip.Prefix{netip.MustParsePrefix("198.19.0.0/16"), {}}); err != nil {
		t.Fatal(err)
	}
	if got := stub.attached["tun"].Required; !slices.Contains(got, netip.MustParsePrefix("198.19.0.0/16")) || slices.Contains(got, netip.MustParsePrefix("198.18.0.0/15")) || server.closed {
		t.Fatalf("after FakeIP change: %v, closed %v", got, server.closed)
	}

	// Stopping detaches before the device closes.
	if err := l.Remove("tun"); err != nil {
		t.Fatal(err)
	}
	if n := len(stub.events); n < 2 || stub.events[n-2] != "detach tun" || stub.events[n-1] != "close" {
		t.Fatalf("events = %v", stub.events)
	}
	if _, ok := stub.attached["tun"]; ok {
		t.Fatal("TUN still attached after removal")
	}

	// fd:// devices (index 0) have host-managed routes and are not attached.
	fd := &linkedServer{events: &stub.events, link: tun.Link{Name: "3"}}
	l.mu.Lock()
	l.attachTun("fd", config, fd)
	l.mu.Unlock()
	if _, ok := stub.attached["fd"]; ok {
		t.Fatal("fd device attached")
	}
}

func TestLegacyRouteFieldsDoNotRebuildTun(t *testing.T) {
	l := NewInbound(netapi.NewErrProxy(errors.New("test proxy")))
	t.Cleanup(func() { _ = l.Close() })
	var events []string
	server := &linkedServer{events: &events}
	config := contract.Inbound{ID: "tun", Name: "tun", Enabled: true, Protocol: contract.NewTypedProtocol(contract.TunProtocol{Name: "tun://utun8"})}
	l.store.Store("tun", entry{contractConfig: &config, server: server})
	legacy := config
	tunConfig := *legacy.Protocol.Tun
	tunConfig.Routes = []string{"0.0.0.0/1"}
	legacy.Protocol.Tun = &tunConfig
	if err := l.SaveContract(legacy); err != nil {
		t.Fatal(err)
	}
	if server.closed {
		t.Fatal("legacy route fields rebuilt the TUN")
	}
}

type memorySysnetStore struct{ config contractsysnet.Config }

func (s *memorySysnetStore) LoadSystemNetwork(context.Context) (contractsysnet.Config, error) { return s.config, nil }
func (s *memorySysnetStore) SaveSystemNetwork(_ context.Context, c contractsysnet.Config) error {
	s.config = c
	return nil
}

// The Android VPN takes its routes from System Network rules: its first
// interface carries them, rule changes reconfigure it in place, and without
// rules the platform route profile applies again.
func TestPlatformTunRoutesFromSystemNetwork(t *testing.T) {
	_, provider := usePlatformStub(t)
	manager := sysnet.New(sysnet.Options{Capabilities: sysnet.PlatformCapabilities("android", false, false),
		Interfaces: func() ([]iface.Info, error) { return nil, nil }})
	t.Cleanup(func() { _ = manager.Close() })
	rule := contractsysnet.RouteRule{ID: "vpn", Name: "VPN", Enabled: true, Priority: 100,
		Match:  contractsysnet.RouteMatch{Mode: contractsysnet.ModeNonPrivate, BypassCIDRs: []string{"8.8.8.0/24"}},
		Target: contractsysnet.RouteTarget{Type: contractsysnet.TargetTunInbound, InboundID: "tun"}}
	store := &memorySysnetStore{config: contractsysnet.Config{Routes: []contractsysnet.RouteRule{rule}}}
	if err := manager.SetStore(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	l := NewInbound(netapi.NewErrProxy(errors.New("test proxy")), WithSystemNetwork(manager))
	t.Cleanup(func() { _ = l.Close() })
	in := platformInbound(true, 1500)
	in.Protocol.Tun.AutoFakeIPRoute = false
	if err := l.SaveContract(in); err != nil {
		t.Fatal(err)
	}
	_, configs := provider.snapshot()
	first := configs[0]
	if len(configs) != 1 || first.RouteMode != platformvpn.RouteModeSystemNetwork {
		t.Fatalf("first interface = %+v (%d establishes)", first, len(configs))
	}
	set := netipSet(t, first.Routes)
	if !set.contains("1.1.1.1") || set.contains("8.8.8.8") || set.contains("192.168.1.1") || set.contains("100.64.0.1") {
		t.Fatalf("routes = %v", first.Routes)
	}
	if s := manager.Status(); s.Rules[0].State != contractsysnet.StateActive || s.Rules[0].IPv4Routes == 0 {
		t.Fatalf("status = %+v", s.Rules)
	}

	// Editing the rule reconfigures the VPN in place.
	rule.Match = contractsysnet.RouteMatch{Mode: contractsysnet.ModeCustom, IncludeCIDRs: []string{"10.10.0.0/16"}}
	if _, err := manager.Save(t.Context(), contractsysnet.Config{Routes: []contractsysnet.RouteRule{rule}}); err != nil {
		t.Fatal(err)
	}
	_, configs = provider.snapshot()
	if last := configs[len(configs)-1]; !slices.Equal(last.Routes, []string{"10.10.0.0/16"}) || last.RouteMode != platformvpn.RouteModeSystemNetwork {
		t.Fatalf("after edit = %+v", last)
	}

	// External interfaces are not offered on Android and are rejected.
	external := rule
	external.ID, external.Target = "wg", contractsysnet.RouteTarget{Type: contractsysnet.TargetInterface, InterfaceName: "wg0"}
	if _, err := manager.Save(t.Context(), contractsysnet.Config{Routes: []contractsysnet.RouteRule{rule, external}}); err == nil {
		t.Fatal("Android accepted an external interface target")
	}

	// No rules: the Android route profile applies again.
	if _, err := manager.Save(t.Context(), contractsysnet.Config{}); err != nil {
		t.Fatal(err)
	}
	_, configs = provider.snapshot()
	if last := configs[len(configs)-1]; last.RouteMode != "" || len(last.Routes) != 0 {
		t.Fatalf("without rules = %+v", last)
	}
}

type prefixSet []netip.Prefix

func netipSet(t *testing.T, routes []string) prefixSet {
	t.Helper()
	var out prefixSet
	for _, r := range routes {
		out = append(out, netip.MustParsePrefix(r))
	}
	return out
}

func (s prefixSet) contains(addr string) bool {
	a := netip.MustParseAddr(addr)
	return slices.ContainsFunc(s, func(p netip.Prefix) bool { return p.Contains(a) })
}
