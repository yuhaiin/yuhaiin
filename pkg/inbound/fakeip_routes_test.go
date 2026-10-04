package inbound

import (
	"errors"
	"net/netip"
	"reflect"
	"sync"
	"testing"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/resolver"
)

type routeAccepterStub struct {
	calls  [][2]netip.Prefix
	closed bool
	fail   bool
}

func (s *routeAccepterStub) Interface() string { return "testtun" }
func (s *routeAccepterStub) Close() error      { s.closed = true; return nil }
func (s *routeAccepterStub) UpdateFakeIPRanges(ranges [2]netip.Prefix) error {
	if s.closed {
		panic("route update after close")
	}
	s.calls = append(s.calls, ranges)
	if s.fail {
		return errors.New("injected route error")
	}
	return nil
}

func TestInboundFakeIPRouteLifecycle(t *testing.T) {
	f, err := resolver.NewFakeDNS(netapi.NewErrProxy(errors.New("test proxy")), netapi.ErrorResolver(func(string) error { return nil }), t.TempDir()+"/state.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	l := NewInbound(netapi.NewErrProxy(errors.New("test proxy")), WithFakeIPRangeSource(f))
	t.Cleanup(func() { _ = l.Close() })
	if l.fakeIPRanges != f.FakeIPRanges() {
		t.Fatal("missing initial runtime snapshot")
	}
	automatic, manual := &routeAccepterStub{}, &routeAccepterStub{}
	config := contract.Inbound{ID: "auto", Name: "auto", Enabled: true, Protocol: contract.NewTypedProtocol(contract.TunProtocol{AutoFakeIPRoute: true, Routes: []string{"192.0.2.0/24"}})}
	manualConfig := contract.Inbound{ID: "manual", Protocol: contract.NewTypedProtocol(contract.TunProtocol{})}
	l.store.Store("auto", entry{contractConfig: &config, server: automatic})
	l.store.Store("manual", entry{contractConfig: &manualConfig, server: manual})
	req := contractresolver.FakeDNS{IPv4Range: "198.19.0.0/16", IPv6Range: "2001:2:0:1::/64"}
	automatic.fail = true
	if err := f.Apply(req); err == nil {
		t.Fatal("sync error did not propagate through the resolver")
	}
	automatic.fail = false
	if err := f.Apply(req); err != nil {
		t.Fatal(err)
	}
	if len(automatic.calls) != 2 || len(manual.calls) != 0 {
		t.Fatal("wrong TUNs were updated or retry was skipped")
	}
	if !reflect.DeepEqual(config.Protocol.Tun.Routes, []string{"192.0.2.0/24"}) {
		t.Fatal("persisted user routes were modified")
	}
	// Closing and a simultaneous pool notification must never update a closed TUN.
	var wg sync.WaitGroup
	wg.Go(func() { _ = f.Apply(req) })
	wg.Go(func() { _ = l.Close() })
	wg.Wait()
	before := len(automatic.calls)
	if err := f.Apply(contractresolver.FakeDNS{}); err != nil {
		t.Fatal(err)
	}
	if len(automatic.calls) != before || !automatic.closed {
		t.Fatal("subscription remained active after close")
	}
}

func TestTunConfigCarriesAutoFlagAndPreservesRouteLists(t *testing.T) {
	config := contract.TunProtocol{AutoFakeIPRoute: true, Routes: []string{"192.0.2.0/24"}, Excludes: []string{"203.0.113.0/24"}}
	got := tunConfig(config)
	if !got.AutoFakeIPRoute || !reflect.DeepEqual(got.Routes, []string{"192.0.2.0/24", "203.0.113.0/24"}) {
		t.Fatalf("unexpected runtime config: %+v", got)
	}
	got.Routes[0] = "changed"
	if config.Routes[0] != "192.0.2.0/24" {
		t.Fatal("runtime config aliases the persisted config")
	}
}

func TestInboundRouteCleanupFailureRemainsRetryable(t *testing.T) {
	l := NewInbound(netapi.NewErrProxy(errors.New("test proxy")))
	t.Cleanup(func() { _ = l.Close() })
	server := &cleanupAccepterStub{fail: true}
	config := contract.Inbound{ID: "tun", Name: "tun", Protocol: contract.NewTypedProtocol(contract.TunProtocol{AutoFakeIPRoute: true})}
	l.store.Store("tun", entry{contractConfig: &config, server: server})
	if err := l.Remove("tun"); err == nil {
		t.Fatal("cleanup error was swallowed")
	}
	if len(l.pendingRouteCleanup) != 1 {
		t.Fatal("failed route cleanup was discarded")
	}
	server.fail = false
	if err := l.UpdateFakeIPRanges([2]netip.Prefix{}); err != nil {
		t.Fatal(err)
	}
	if len(l.pendingRouteCleanup) != 0 || server.closes != 2 {
		t.Fatal("range synchronization did not retry retired TUN cleanup")
	}
	// Repeated runtime Close retries cleanup even after subscriptions are cancelled.
	server.fail = true
	l.store.Store("tun", entry{contractConfig: &config, server: server})
	if err := l.Close(); err == nil {
		t.Fatal("runtime Close swallowed route cleanup error")
	}
	server.fail = false
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if len(l.pendingRouteCleanup) != 0 {
		t.Fatal("repeated Close did not retry cleanup")
	}
}

type cleanupAccepterStub struct {
	fail   bool
	closes int
}

func (s *cleanupAccepterStub) Interface() string                        { return "testtun" }
func (s *cleanupAccepterStub) UpdateFakeIPRanges([2]netip.Prefix) error { return nil }
func (s *cleanupAccepterStub) Close() error {
	s.closes++
	if s.fail {
		return errors.New("route cleanup failed")
	}
	return nil
}

func TestInboundSavingUnchangedTUNRetriesRoutesWithoutRestart(t *testing.T) {
	l := NewInbound(netapi.NewErrProxy(errors.New("test proxy")))
	t.Cleanup(func() { _ = l.Close() })
	server := &routeAccepterStub{}
	config := contract.Inbound{ID: "tun", Name: "tun", Enabled: true, Protocol: contract.NewTypedProtocol(contract.TunProtocol{AutoFakeIPRoute: true})}
	l.store.Store("tun", entry{contractConfig: &config, server: server})
	if err := l.SaveContract(config); err != nil {
		t.Fatal(err)
	}
	if server.closed || len(server.calls) != 1 {
		t.Fatal("saving unchanged config did not retry routes in place")
	}
	disabled := config
	disabled.Enabled = false
	if err := l.SaveContract(disabled); err != nil {
		t.Fatal(err)
	}
	if !server.closed || l.Interfaces().Len() != 0 {
		t.Fatal("disabled TUN was not removed")
	}
}
