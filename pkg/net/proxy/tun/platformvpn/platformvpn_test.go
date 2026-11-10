package platformvpn

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/device"
)

type fakeProvider struct {
	mu        sync.Mutex
	next      int
	live      map[uint64]int
	released  []uint64
	configs   []Config
	fail      error
	establish atomic.Int32
}

func (p *fakeProvider) Establish(_ context.Context, gen uint64, c Config) (int, error) {
	p.establish.Add(1)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.fail != nil {
		return -1, p.fail
	}
	if p.live == nil {
		p.live = map[uint64]int{}
	}
	p.next++
	p.live[gen] = 100 + p.next
	p.configs = append(p.configs, c)
	return 100 + p.next, nil
}

func (p *fakeProvider) Release(gen uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.live[gen]; ok {
		delete(p.live, gen)
		p.released = append(p.released, gen)
	}
}

func (p *fakeProvider) liveCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.live)
}

type fakeStack struct {
	netapi.EmptyInterface
	name   string
	closes atomic.Int32
}

func (s *fakeStack) Close() error { s.closes.Add(1); return nil }

type opener struct {
	mu     sync.Mutex
	stacks []*fakeStack
	fail   error
}

func (o *opener) open(c device.TunConfig) (netapi.Accepter, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.fail != nil {
		err := o.fail
		o.fail = nil
		return nil, err
	}
	s := &fakeStack{name: c.Name}
	o.stacks = append(o.stacks, s)
	return s, nil
}

var ranges = [2]netip.Prefix{netip.MustParsePrefix("198.18.0.0/16"), netip.MustParsePrefix("2001:2::/64")}

func newTestManager(p Provider) *Manager {
	m := NewManager()
	m.Debounce = 10 * time.Millisecond
	m.SetProvider(p)
	return m
}

func spec() Spec {
	return Spec{Stack: device.TunConfig{Portal: "172.19.0.1/24", PortalV6: "fdfe:dcba:9876::1/64", MTU: 9000}, AutoFakeIPRoute: true}
}

func TestStartBuildsConfigFromCoreFakeIPPools(t *testing.T) {
	p := &fakeProvider{}
	o := &opener{}
	m := newTestManager(p)
	a, err := m.New("tun", spec(), ranges, o.open)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	got := p.configs[0]
	if got.MTU != 9000 || got.IPv4 != "172.19.0.1" || got.IPv4Prefix != 24 || got.DNS[0] != "172.19.0.2" {
		t.Fatalf("config = %+v", got)
	}
	if len(got.FakeIPRoutes) == 0 || got.FakeIPRoutes[0] != "198.18.0.0/16" {
		t.Fatalf("fake IP routes = %v", got.FakeIPRoutes)
	}
	if o.stacks[0].name != "fd://101" {
		t.Fatalf("stack uses %q", o.stacks[0].name)
	}
	if s := m.Status(); s.State != StateRunning || s.Generation != a.Generation() || s.Applied == nil {
		t.Fatalf("status = %+v", s)
	}
}

func TestUnchangedFakeIPUpdateDoesNotReconfigure(t *testing.T) {
	p := &fakeProvider{}
	m := newTestManager(p)
	a, err := m.New("tun", spec(), ranges, (&opener{}).open)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	_ = a.UpdateFakeIPRanges(ranges)
	if err := a.Apply(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	if n := p.establish.Load(); n != 1 {
		t.Fatalf("establish calls = %d, want 1", n)
	}
}

func TestFakeIPChangeReconfiguresMakeBeforeBreak(t *testing.T) {
	p := &fakeProvider{}
	o := &opener{}
	m := newTestManager(p)
	a, err := m.New("tun", spec(), ranges, o.open)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	first := a.Generation()
	next := [2]netip.Prefix{netip.MustParsePrefix("100.64.0.0/16"), ranges[1]}
	// A burst collapses into one rebuild.
	for range 5 {
		_ = a.UpdateFakeIPRanges(next)
	}
	deadline := time.Now().Add(2 * time.Second)
	for a.Generation() == first && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if a.Generation() == first {
		t.Fatal("not reconfigured")
	}
	if n := p.establish.Load(); n != 2 {
		t.Fatalf("establish calls = %d, want 2", n)
	}
	if o.stacks[0].closes.Load() != 1 || o.stacks[1].closes.Load() != 0 {
		t.Fatal("old stack must close after the new one starts")
	}
	if p.liveCount() != 1 || p.released[0] != first {
		t.Fatalf("live=%d released=%v", p.liveCount(), p.released)
	}
	s := m.Status()
	if s.Applied.FakeIPRoutes[0] != "100.64.0.0/16" || s.Reconfigurations != 1 || s.Pending != nil {
		t.Fatalf("status = %+v", s)
	}
}

func TestEstablishFailureKeepsPreviousInterface(t *testing.T) {
	p := &fakeProvider{}
	o := &opener{}
	m := newTestManager(p)
	a, err := m.New("tun", spec(), ranges, o.open)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	gen := a.Generation()
	p.mu.Lock()
	p.fail = errors.New("permission_required: VpnService.prepare")
	p.mu.Unlock()
	sp := spec()
	sp.Stack.MTU = 1500
	err = a.Reconfigure(sp)
	if ErrorCode(err) != CodePermissionRequired {
		t.Fatalf("err = %v", err)
	}
	if a.Generation() != gen || o.stacks[0].closes.Load() != 0 {
		t.Fatal("previous interface must survive a refused reconfiguration")
	}
	s := m.Status()
	if s.State != StateRunning || s.ErrorCode != CodePermissionRequired || s.Applied.MTU != 9000 || s.ReconfigureFailures != 1 {
		t.Fatalf("status = %+v", s)
	}
}

func TestStackFailureRestoresPreviousConfiguration(t *testing.T) {
	p := &fakeProvider{}
	o := &opener{}
	m := newTestManager(p)
	a, err := m.New("tun", spec(), ranges, o.open)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	o.mu.Lock()
	o.fail = errors.New("boom")
	o.mu.Unlock()
	sp := spec()
	sp.Stack.MTU = 1400
	if err := a.Reconfigure(sp); err == nil {
		t.Fatal("expected failure")
	}
	s := m.Status()
	if s.State != StateRunning || s.Applied.MTU != 9000 {
		t.Fatalf("status = %+v", s)
	}
	last := p.configs[len(p.configs)-1]
	if last.MTU != 9000 {
		t.Fatalf("recovery used %+v", last)
	}
	if p.liveCount() != 1 {
		t.Fatalf("live = %d", p.liveCount())
	}
}

func TestStartFailureIsReportedAndReleased(t *testing.T) {
	p := &fakeProvider{fail: errors.New("consent_required: disclosure")}
	m := newTestManager(p)
	if _, err := m.New("tun", spec(), ranges, (&opener{}).open); ErrorCode(err) != CodeConsentRequired {
		t.Fatalf("err = %v", err)
	}
	if s := m.Status(); s.State != StateFailed || s.ErrorCode != CodeConsentRequired {
		t.Fatalf("status = %+v", s)
	}
	if _, ok := m.Active(); ok {
		t.Fatal("failed start must not stay active")
	}
	p.mu.Lock()
	p.fail = nil
	p.mu.Unlock()
	a, err := m.New("tun", spec(), ranges, (&opener{}).open)
	if err != nil {
		t.Fatal(err)
	}
	_ = a.Close()
}

func TestNoProvider(t *testing.T) {
	m := NewManager()
	if _, err := m.New("tun", spec(), ranges, (&opener{}).open); ErrorCode(err) != CodeProviderUnavailable {
		t.Fatalf("err = %v", err)
	}
}

func TestSecondPlatformVPNIsRejected(t *testing.T) {
	m := newTestManager(&fakeProvider{})
	a, err := m.New("a", spec(), ranges, (&opener{}).open)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if _, err := m.New("b", spec(), ranges, (&opener{}).open); ErrorCode(err) != CodeBusy {
		t.Fatalf("err = %v", err)
	}
}

func TestCloseIsIdempotentAndReleases(t *testing.T) {
	p := &fakeProvider{}
	o := &opener{}
	m := newTestManager(p)
	a, err := m.New("tun", spec(), ranges, o.open)
	if err != nil {
		t.Fatal(err)
	}
	_ = a.Close()
	_ = a.Close()
	if p.liveCount() != 0 || o.stacks[0].closes.Load() != 1 {
		t.Fatalf("live=%d closes=%d", p.liveCount(), o.stacks[0].closes.Load())
	}
	if s := m.Status(); s.State != StateStopped {
		t.Fatalf("status = %+v", s)
	}
}

func TestStaleRevokeIsIgnored(t *testing.T) {
	p := &fakeProvider{}
	m := newTestManager(p)
	a, err := m.New("tun", spec(), ranges, (&opener{}).open)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	old := a.Generation()
	m.RequestReconfigure()
	deadline := time.Now().Add(2 * time.Second)
	for a.Generation() == old && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if m.Revoked(old) {
		t.Fatal("stale revoke stopped the new interface")
	}
	if !m.Revoked(a.Generation()) {
		t.Fatal("current revoke ignored")
	}
	if s := m.Status(); s.State != StateRevoked || s.ErrorCode != CodeRevoked {
		t.Fatalf("status = %+v", s)
	}
	_ = a.Close()
	if s := m.Status(); s.State != StateRevoked {
		t.Fatal("close must keep the revoke reason")
	}
	if p.liveCount() != 0 {
		t.Fatal("revoke leaked an interface")
	}
}

func TestConcurrentOperationsAreSerialized(t *testing.T) {
	p := &fakeProvider{}
	m := newTestManager(p)
	m.Debounce = 0
	a, err := m.New("tun", spec(), ranges, (&opener{}).open)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Go(func() {
			sp := spec()
			sp.Stack.MTU = int32(1400 + i%3)
			_ = a.Reconfigure(sp)
			m.RequestReconfigure()
		})
	}
	wg.Wait()
	_ = a.Close()
	if p.liveCount() != 0 {
		t.Fatalf("leaked %d interfaces", p.liveCount())
	}
}

func TestErrorCodeFromForeignMessage(t *testing.T) {
	for msg, want := range map[string]string{
		"java.lang.IllegalStateException: permission_required: prepare": CodePermissionRequired,
		"consent_required: VPN disclosure":                              CodeConsentRequired,
		"something else":                                                CodeEstablishFailed,
	} {
		if got := ErrorCode(errors.New(msg)); got != want {
			t.Errorf("%q => %q, want %q", msg, got, want)
		}
	}
}
