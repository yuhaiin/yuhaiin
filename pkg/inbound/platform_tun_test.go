package inbound

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/device"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/platformvpn"
	"github.com/Asutorufa/yuhaiin/pkg/resolver"
)

type platformProviderStub struct {
	mu      sync.Mutex
	live    map[uint64]platformvpn.Config
	configs []platformvpn.Config
	err     error
}

func (p *platformProviderStub) Establish(_ context.Context, gen uint64, c platformvpn.Config) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return -1, p.err
	}
	if p.live == nil {
		p.live = map[uint64]platformvpn.Config{}
	}
	p.live[gen] = c
	p.configs = append(p.configs, c)
	return 3, nil
}

func (p *platformProviderStub) Release(gen uint64) {
	p.mu.Lock()
	delete(p.live, gen)
	p.mu.Unlock()
}

func (p *platformProviderStub) snapshot() (int, []platformvpn.Config) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.live), append([]platformvpn.Config(nil), p.configs...)
}

type platformStackStub struct{ netapi.EmptyInterface }

func (platformStackStub) Close() error { return nil }

func usePlatformStub(t *testing.T) (*platformvpn.Manager, *platformProviderStub) {
	t.Helper()
	m := platformvpn.NewManager()
	m.Debounce = time.Millisecond
	p := &platformProviderStub{}
	m.SetProvider(p)
	oldManager, oldOpen := platformTunManager, platformTunOpen
	platformTunManager = m
	platformTunOpen = func(device.TunConfig, netapi.Handler) (netapi.Accepter, error) { return platformStackStub{}, nil }
	t.Cleanup(func() { platformTunManager, platformTunOpen = oldManager, oldOpen })
	return m, p
}

func platformInbound(enabled bool, mtu int32) contract.Inbound {
	return contract.Inbound{ID: "tun", Name: "tun", Enabled: enabled,
		Network: contract.NewTypedNetwork(contract.EmptyNetwork{}),
		Protocol: contract.NewTypedProtocol(contract.TunProtocol{Name: platformvpn.DeviceName, MTU: mtu,
			Portal: "172.19.0.1/24", PortalV6: "fdfe::1/64", AutoFakeIPRoute: true, Stack: "lightweight"})}
}

func TestPlatformTunLifecycleThroughInboundRuntime(t *testing.T) {
	m, p := usePlatformStub(t)
	f, err := resolver.NewFakeDNS(netapi.NewErrProxy(errors.New("test proxy")), netapi.ErrorResolver(func(string) error { return nil }), t.TempDir()+"/state.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	l := NewInbound(netapi.NewErrProxy(errors.New("test proxy")), WithFakeIPRangeSource(f))
	t.Cleanup(func() { _ = l.Close() })

	// Disabled: the core runs without any VPN interface.
	if err := l.SaveContract(platformInbound(false, 9000)); err != nil {
		t.Fatal(err)
	}
	if n, _ := p.snapshot(); n != 0 {
		t.Fatal("disabled inbound created a VPN")
	}

	if err := l.SaveContract(platformInbound(true, 9000)); err != nil {
		t.Fatal(err)
	}
	first, _ := l.store.Load("tun")
	gen := m.Status().Generation
	_, configs := p.snapshot()
	if configs[0].FakeIPRoutes[0] != f.FakeIPRanges()[0].String() {
		t.Fatalf("VPN routes %v do not match the active pool %v", configs[0].FakeIPRoutes, f.FakeIPRanges())
	}

	// Same request is idempotent.
	if err := l.SaveContract(platformInbound(true, 9000)); err != nil {
		t.Fatal(err)
	}
	if m.Status().Generation != gen {
		t.Fatal("unchanged save rebuilt the VPN")
	}

	// FakeIP pool change reconfigures the VPN without touching the listener.
	if err := f.Apply(contractresolver.FakeDNS{IPv4Range: "198.19.0.0/16", IPv6Range: "2001:2:0:1::/64"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return m.Status().Generation != gen })
	if got := m.Status().Applied.FakeIPRoutes[0]; got != "198.19.0.0/16" {
		t.Fatalf("applied FakeIP route %q", got)
	}

	// MTU change is applied in place: same server, new generation.
	gen = m.Status().Generation
	if err := l.SaveContract(platformInbound(true, 1500)); err != nil {
		t.Fatal(err)
	}
	second, _ := l.store.Load("tun")
	if second.server != first.server || m.Status().Generation == gen || m.Status().Applied.MTU != 1500 {
		t.Fatal("MTU change was not applied in place")
	}
	if n, _ := p.snapshot(); n != 1 {
		t.Fatalf("live interfaces = %d", n)
	}

	// Disabling releases the interface; the runtime stays open.
	if err := l.SaveContract(platformInbound(false, 1500)); err != nil {
		t.Fatal(err)
	}
	if n, _ := p.snapshot(); n != 0 {
		t.Fatal("disable leaked the VPN interface")
	}
	if l.closed {
		t.Fatal("runtime closed")
	}
}

func TestPlatformTunFailureIsInboundStateOnly(t *testing.T) {
	_, p := usePlatformStub(t)
	p.err = errors.New("permission_required: VpnService.prepare returned an intent")
	l := NewInbound(netapi.NewErrProxy(errors.New("test proxy")))
	t.Cleanup(func() { _ = l.Close() })
	err := l.SaveContract(platformInbound(true, 9000))
	if platformvpn.ErrorCode(err) != platformvpn.CodePermissionRequired {
		t.Fatalf("err = %v", err)
	}
	status := l.runtimeStatus(platformInbound(true, 9000))
	if status.Status != "failed" || status.LastError == "" {
		t.Fatalf("status = %+v", status)
	}
	// The same request retries once permission exists.
	p.mu.Lock()
	p.err = nil
	p.mu.Unlock()
	if err := l.SaveContract(platformInbound(true, 9000)); err != nil {
		t.Fatal(err)
	}
	if got := l.runtimeStatus(platformInbound(true, 9000)).Status; got != "running" {
		t.Fatalf("status = %s", got)
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
