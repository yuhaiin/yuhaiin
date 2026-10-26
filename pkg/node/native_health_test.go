package node

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type nativeStatusTestProxy struct {
	netapi.Proxy
	status contract.ProtocolRuntimeStatus
}

func (p *nativeStatusTestProxy) NodeRuntimeStatus() contract.ProtocolRuntimeStatus { return p.status }

func TestNativeProbeSeparatesControlConfigurationAndTunnelSession(t *testing.T) {
	r := newTestRuntime(t)
	n := testNode(t, "a", "a")
	if _, err := r.Save(t.Context(), n); err != nil {
		t.Fatal(err)
	}
	p := &nativeStatusTestProxy{Proxy: netapi.NewErrProxy(errors.New("native inspection must not dial"))}
	if _, err := r.proxies.LoadOrCreate(t.Context(), n.ID, func() (*ProxyEntry, error) { return &ProxyEntry{Proxy: p}, nil }); err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"idle", "connecting", "configured", "closed", "reconnecting", "unknown", "control_unavailable", "authentication_failed"} {
		p.status = contract.ProtocolRuntimeStatus{State: state, UpdatedAt: time.Now().Unix()}
		if err := r.selectors.nativeProbe(t.Context(), n.ID); !errors.Is(err, errProbeSkipped) {
			t.Fatal(state, err)
		}
	}
	if len(r.observer.counter(n.ID).snapshot().TCPHealth.Samples) != 0 {
		t.Fatal("control/config state inferred a data handshake")
	}
	for _, state := range []string{"connected", "failed"} {
		p.status = contract.ProtocolRuntimeStatus{State: state, UpdatedAt: time.Now().Unix()}
		err := r.selectors.nativeProbe(t.Context(), n.ID)
		if (err == nil) != (state == "connected") {
			t.Fatal(state, err)
		}
	}
	v := r.observer.counter(n.ID).snapshot()
	for _, h := range []contract.ChannelHealth{v.TCPHealth, v.UDPHealth} {
		if len(h.Samples) != 2 || !h.Samples[0].OK || h.Samples[1].OK || h.Samples[0].Kind != "native" {
			t.Fatal(h)
		}
	}
}
func TestBackgroundNodeFactoryCannotStartExpiredCachedVPN(t *testing.T) {
	r := newTestRuntime(t)
	n := testNode(t, "a", "a")
	n.Chain = []contract.Protocol{{Type: "tailscale", Tailscale: &contract.Tailscale{AuthKey: "local-test-placeholder"}}}
	if _, err := r.Save(t.Context(), n); err != nil {
		t.Fatal(err)
	}
	_, epoch, err := r.cachedNode(t.Context(), n.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.getContractDialer(netapi.WithBackgroundProbe(t.Context()), n.ID, n, epoch); !errors.Is(err, netapi.ErrBackgroundProbeUnavailable) {
		t.Fatal(err)
	}
	if _, ok := r.proxies.store.Load(n.ID); ok {
		t.Fatal("periodic factory constructed a VPN")
	}
	if !localProbeDenial(netapi.ErrBackgroundProbeUnavailable) || healthFailure(netapi.ErrBackgroundProbeUnavailable) {
		t.Fatal("local reuse denial classified as remote failure")
	}
}

func TestAuthenticationStateFiltersWithoutInventingTransportFailure(t *testing.T) {
	r, s := qualificationSelector(t, "failover")
	svc := NewSelectorService(r)
	p, _ := r.proxies.store.Load("a")
	p.mu.Lock()
	p.Proxy = &nativeStatusTestProxy{Proxy: p.Proxy, status: contract.ProtocolRuntimeStatus{State: "authentication_failed", UpdatedAt: time.Now().Unix()}}
	p.mu.Unlock()
	r.selectors.mu.Lock()
	r.selectors.rebuild(time.Now())
	r.selectors.mu.Unlock()
	status, err := svc.Status(t.Context(), s.ID)
	if err != nil || status.TCP.NodeID != "b" || status.UDP.NodeID != "b" {
		t.Fatal(status, err)
	}
	if status.TCP.Candidates[0].Reason != "authentication_unavailable" {
		t.Fatal(status.TCP)
	}
	stats := r.observer.counter("a").snapshot()
	if stats.TCPHealth.ConsecutiveFailures != 0 || r.observer.counter("a").failures.Load() != 0 {
		t.Fatal("authentication state inflated network failures", stats)
	}
	// Neither unknown fallback nor selected fallback revives an unusable login.
	now := time.Now()
	selector, inputs := selectionFixture(now)
	for i := range inputs {
		inputs[i].unavailableReason = "authentication_unavailable"
		inputs[i].health = contract.ChannelHealth{}
	}
	for _, fallback := range []string{"selected", "priority_unknown"} {
		selector.Policy.Fallback = fallback
		if d := evaluateSelector(selector, inputs, contract.SelectorDecision{}, now); d.NodeID != "" {
			t.Fatal(fallback, d)
		}
	}
	selector.Policy.Locked = true
	if d := evaluateSelector(selector, inputs, contract.SelectorDecision{}, now); d.NodeID != "a" {
		t.Fatal("manual behavior changed", d)
	}
}

func TestBackgroundProbeCannotAuthenticateThroughCachedSet(t *testing.T) {
	r := newTestRuntime(t)
	n := testNode(t, "vpn", "vpn")
	n.Chain = []contract.Protocol{{Type: "tailscale", Tailscale: &contract.Tailscale{AuthKey: "local-test-placeholder"}}}
	if _, err := r.Save(t.Context(), n); err != nil {
		t.Fatal(err)
	}
	set, err := NewContractSet([]string{n.ID}, "round_robin", r)
	if err != nil {
		t.Fatal(err)
	}
	defer set.Close()
	a, _ := netapi.ParseAddress("tcp", "192.0.2.1:443")
	if _, err := set.Conn(netapi.WithBackgroundProbe(t.Context()), a); !errors.Is(err, netapi.ErrBackgroundProbeUnavailable) {
		t.Fatal(err)
	}
	if _, ok := r.proxies.store.Load(n.ID); ok {
		t.Fatal("Set dropped background context and constructed VPN")
	}
}
func TestNativeProbeRejectsStaleAndFutureSessionSnapshots(t *testing.T) {
	r := newTestRuntime(t)
	n := testNode(t, "a", "a")
	if _, err := r.Save(t.Context(), n); err != nil {
		t.Fatal(err)
	}
	p := &nativeStatusTestProxy{Proxy: netapi.NewErrProxy(errors.New("must not dial"))}
	if _, err := r.proxies.LoadOrCreate(t.Context(), n.ID, func() (*ProxyEntry, error) { return &ProxyEntry{Proxy: p}, nil }); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, at := range []int64{0, now.Add(-121 * time.Second).Unix(), now.Add(time.Minute).Unix()} {
		p.status = contract.ProtocolRuntimeStatus{State: "connected", UpdatedAt: at}
		if err := r.selectors.nativeProbe(t.Context(), n.ID); !errors.Is(err, errProbeSkipped) {
			t.Fatal(at, err)
		}
	}
	if len(r.observer.counter(n.ID).snapshot().TCPHealth.Samples) != 0 {
		t.Fatal("invalid native evidence accepted")
	}
}

func BenchmarkNativeSelectionAvailability(b *testing.B) {
	for _, count := range []int{100, 1000} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			r := NewNodeRuntime(b.TempDir() + "/unused.db")
			defer r.Close()
			now := time.Now()
			for i := range count {
				state := "connected"
				if i%10 == 0 {
					state = "authentication_failed"
				}
				p := &nativeStatusTestProxy{Proxy: netapi.NewErrProxy(errors.New("unused")), status: contract.ProtocolRuntimeStatus{State: state, UpdatedAt: now.Unix()}}
				if _, err := r.proxies.LoadOrCreate(b.Context(), fmt.Sprint(i), func() (*ProxyEntry, error) { return &ProxyEntry{Proxy: p}, nil }); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if v := r.nativeSelectionUnavailable(now); len(v) != count/10 {
					b.Fatal(len(v))
				}
			}
		})
	}
}
func TestNativeUnavailableSnapshotNeverWaitsForProxyClose(t *testing.T) {
	r := newTestRuntime(t)
	if _, err := r.Save(t.Context(), testNode(t, "a", "a")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.proxies.LoadOrCreate(t.Context(), "a", func() (*ProxyEntry, error) { return &ProxyEntry{Proxy: netapi.NewErrProxy(errors.New("unused"))}, nil }); err != nil {
		t.Fatal(err)
	}
	p, _ := r.proxies.store.Load("a")
	p.mu.Lock()
	defer p.mu.Unlock()
	done := make(chan struct{})
	go func() {
		r.nativeSelectionUnavailable(time.Now())
		_, _ = r.Statuses(t.Context(), []string{"a"})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("native status snapshot waited on closing proxy")
	}
}

func TestNativeAvailabilityReadsOnlyFreshSessionState(t *testing.T) {
	r := NewNodeRuntime(t.TempDir() + "/unused.db")
	defer r.Close()
	p := &nativeStatusTestProxy{Proxy: netapi.NewErrProxy(errors.New("unused"))}
	if _, err := r.proxies.LoadOrCreate(t.Context(), "a", func() (*ProxyEntry, error) { return &ProxyEntry{Proxy: p}, nil }); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, tc := range []struct{ state, want string }{{"authentication_failed", "authentication_unavailable"}, {"closed", "session_unavailable"}, {"disconnected", "session_unavailable"}, {"reconnecting", "session_unavailable"}, {"failed", "session_unavailable"}, {"control_unavailable", "control_unavailable"}, {"connected", ""}, {"configured", ""}, {"idle", ""}, {"connecting", ""}} {
		p.status = contract.ProtocolRuntimeStatus{State: tc.state, UpdatedAt: now.Unix()}
		if got := r.nativeSelectionUnavailable(now)["a"]; got != tc.want {
			t.Fatal(tc, got)
		}
	}
	p.status = contract.ProtocolRuntimeStatus{State: "authentication_failed", UpdatedAt: now.Add(-121 * time.Second).Unix()}
	if got := r.nativeSelectionUnavailable(now); len(got) != 0 {
		t.Fatal("expired state blocked candidate", got)
	}
	if _, err := os.Stat(r.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("native snapshot opened SQLite", err)
	}
}

func TestUnavailableCandidateKeepsRawMeasurementEvidence(t *testing.T) {
	now := time.Now()
	selector, inputs := selectionFixture(now)
	inputs[0].unavailableReason = "authentication_unavailable"
	candidate := scoreCandidate(selector.Policy.Effective(), inputs[0], now)
	if candidate.Eligible || candidate.Reason != "authentication_unavailable" || candidate.RTTMS <= 0 || candidate.DownloadMbps <= 0 {
		t.Fatal(candidate)
	}
}

func TestBackgroundReuseDenialWrappedWithNetworkErrorRemainsLocal(t *testing.T) {
	err := errors.Join(netapi.ErrBackgroundProbeUnavailable, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED})
	if healthFailure(err) || circuitIOFailure(err) || !localProbeDenial(err) {
		t.Fatal("compound local denial became node failure")
	}
	c := new(nodeCounters)
	c.remoteEvidence(true, contract.HealthSample{Kind: "tcp_connect"}, err)
	if len(c.snapshot().TCPHealth.Samples) != 0 {
		t.Fatal("local denial changed transport health")
	}
}
