package node

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	"github.com/prometheus/client_golang/prometheus"
)

func TestAutomaticSelectorDoesNotReplayPOSTAndKeepsBusiness4xxHealthy(t *testing.T) {
	r := newTestRuntime(t)
	var firstCalls, secondCalls atomic.Int32
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		firstCalls.Add(1)
		if _, err := io.Copy(io.Discard, request.Body); err != nil {
			t.Error(err)
		}
		connection, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		// The peer accepted the complete non-idempotent request before resetting
		// the transport. Another outbound must not execute it a second time.
		if tcp, ok := connection.(*net.TCPConn); ok {
			_ = tcp.SetLinger(0)
		}
		_ = connection.Close()
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		secondCalls.Add(1)
		_, _ = io.Copy(io.Discard, request.Body)
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("application response"))
	}))
	defer second.Close()
	for id, listener := range map[string]string{"a": first.Listener.Addr().String(), "b": second.Listener.Addr().String()} {
		if _, err := r.Save(t.Context(), testNode(t, id, id)); err != nil {
			t.Fatal(err)
		}
		counter := r.observer.counter(id)
		for range 3 {
			counter.remoteEvidence(true, contract.HealthSample{Kind: "connect", OK: true}, nil)
		}
		proxy := &observedProxy{c: counter, epoch: counter.generation.Load(), Proxy: observedTestProxy{connect: func() (net.Conn, error) {
			return new(net.Dialer).DialContext(t.Context(), "tcp", listener)
		}}}
		if _, err := r.proxies.LoadOrCreate(t.Context(), id, func() (*ProxyEntry, error) { return &ProxyEntry{Proxy: proxy, Name: id}, nil }); err != nil {
			t.Fatal(err)
		}
	}
	selector, err := NewSelectorService(r).Save(t.Context(), contract.Selector{Name: "HTTP no replay", NodeID: "a", Policy: &contract.SelectorPolicy{Mode: "failover", FailureThreshold: 1,
		Candidates: []contract.SelectorCandidate{{NodeID: "a", Enabled: true, Weight: 1}, {NodeID: "b", Enabled: true, Weight: 1, Priority: 1}}}})
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := r.GetTarget(t.Context(), "tcp", "proxy", contractroute.Target{Type: "selector", ID: selector.ID})
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		parsed, err := netapi.ParseAddress(network, address)
		if err != nil {
			return nil, err
		}
		return proxy.Conn(netapi.WithContext(ctx), parsed)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	response, err := client.Post(first.URL, "text/plain", strings.NewReader("execute this request only once"))
	if response != nil {
		_ = response.Body.Close()
	}
	if err == nil || firstCalls.Load() != 1 || secondCalls.Load() != 0 {
		t.Fatal("ambiguous POST was replayed", firstCalls.Load(), secondCalls.Load(), err)
	}
	r.selectors.mu.Lock()
	r.selectors.rebuild(time.Now())
	r.selectors.mu.Unlock()
	response, err = client.Post(first.URL, "text/plain", strings.NewReader("a separately submitted request"))
	if err != nil {
		t.Fatal("a new request did not fail over", err)
	}
	_, readErr := io.Copy(io.Discard, response.Body)
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || response.StatusCode != http.StatusForbidden || firstCalls.Load() != 1 || secondCalls.Load() != 1 {
		t.Fatal("unexpected independent request result", readErr, closeErr, response.StatusCode, firstCalls.Load(), secondCalls.Load())
	}
	if state := r.selectors.circuitBindings[selector.ID]["b"].tcp.snapshot(time.Now()); state.State != "closed" || r.observer.counter("b").snapshot().TCPHealth.ConsecutiveFailures != 0 {
		t.Fatal("HTTP business response condemned the outbound", state)
	}
}

func TestSelectorRuntimeNoDatabaseOnConnectionPathAndLiveReload(t *testing.T) {
	r := newTestRuntime(t)
	for _, id := range []string{"a", "b"} {
		if _, err := r.Save(t.Context(), testNode(t, id, id)); err != nil {
			t.Fatal(err)
		}
	}
	svc := NewSelectorService(r)
	s, err := svc.Save(t.Context(), contract.Selector{Name: "Auto", NodeID: "a", Policy: &contract.SelectorPolicy{Mode: "failover", Fallback: "priority_unknown", Candidates: []contract.SelectorCandidate{{NodeID: "a", Enabled: true, Weight: 1}, {NodeID: "b", Enabled: true, Priority: 1, Weight: 1}}}})
	if err != nil {
		t.Fatal(err)
	}
	// Reserve the only DB connection. A selector target must still resolve.
	lease, err := r.sqlite.DB().Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	p, err := r.GetTarget(ctx, "tcp", "proxy", contractroute.Target{Type: "selector", ID: s.ID})
	cancel()
	_ = lease.Close()
	if err != nil || p == nil {
		t.Fatal("selector attempted SQLite access on connection path", err)
	}
	s.NodeID = "b"
	s.Policy.Locked = true
	s, err = svc.Save(t.Context(), s)
	if err != nil {
		t.Fatal(err)
	}
	status, err := svc.Status(t.Context(), s.ID)
	if err != nil || status.TCP.NodeID != "b" || status.UDP.NodeID != "b" || status.Revision != s.Revision {
		t.Fatal(status, err)
	}
	if err := svc.Delete(t.Context(), s.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := r.GetTarget(t.Context(), "tcp", "proxy", contractroute.Target{Type: "selector", ID: s.ID}); err == nil {
		t.Fatal("deleted selector still active")
	}
}

func TestSelectorSnapshotsKeepNodeGenerationAcrossReload(t *testing.T) {
	r := newTestRuntime(t)
	node := testNode(t, "a", "before")
	if _, err := r.Save(t.Context(), node); err != nil {
		t.Fatal(err)
	}
	svc := NewSelectorService(r)
	first, err := svc.Save(t.Context(), contract.Selector{Name: "First", NodeID: node.ID})
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.Save(t.Context(), contract.Selector{Name: "Second", NodeID: node.ID})
	if err != nil {
		t.Fatal(err)
	}
	old := r.selectors.snapshot.Load()
	node.Name = "after"
	if _, err := r.Save(t.Context(), node); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Save(t.Context(), testNode(t, "b", "added")); err != nil {
		t.Fatal(err)
	}
	current := r.selectors.snapshot.Load()
	for _, id := range []string{first.ID, second.ID} {
		if got := old.items[id].nodes[node.ID].Name; got != "before" {
			t.Fatalf("old selector %s node changed to %q", id, got)
		}
		if got := current.items[id].nodes[node.ID].Name; got != "after" {
			t.Fatalf("current selector %s node name = %q", id, got)
		}
	}
}

func TestSelectorConcurrentSnapshotChanges(t *testing.T) {
	r := newTestRuntime(t)
	for _, id := range []string{"a", "b"} {
		if _, err := r.Save(t.Context(), testNode(t, id, id)); err != nil {
			t.Fatal(err)
		}
	}
	svc := NewSelectorService(r)
	s, err := svc.Save(t.Context(), contract.Selector{Name: "Concurrent", NodeID: "a"})
	if err != nil {
		t.Fatal(err)
	}
	selectorID := s.ID
	var wg sync.WaitGroup
	for range 1000 {
		wg.Go(func() {
			for range 10 {
				ctx := netapi.WithContext(t.Context())
				if _, err := r.GetTarget(ctx, "tcp", "proxy", contractroute.Target{Type: "selector", ID: selectorID}); err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	for i := range 20 {
		next := s
		next.NodeID = []string{"a", "b"}[i%2]
		updated, err := svc.Save(t.Context(), next)
		if err != nil {
			t.Fatal(err)
		}
		s = updated
	}
	wg.Wait()
}

type pinnedTestProxy struct {
	netapi.EmptyDispatch
	tcp atomicTestDial
}
type atomicTestDial struct {
	mu    sync.Mutex
	count int
}

func (p *pinnedTestProxy) Conn(context.Context, netapi.Address) (net.Conn, error) {
	p.tcp.mu.Lock()
	p.tcp.count++
	p.tcp.mu.Unlock()
	a, b := net.Pipe()
	go func() { defer b.Close(); _, _ = b.Write([]byte("pinned")) }()
	return a, nil
}
func (*pinnedTestProxy) PacketConn(context.Context, netapi.Address) (net.PacketConn, error) {
	return nil, fmt.Errorf("not used")
}
func (*pinnedTestProxy) Ping(context.Context, netapi.Address) (uint64, error) { return 0, nil }
func (*pinnedTestProxy) Close() error                                         { return nil }

func TestSelectorSwitchDoesNotReplayOrCloseEstablishedStream(t *testing.T) {
	r := newTestRuntime(t)
	for _, id := range []string{"a", "b"} {
		if _, err := r.Save(t.Context(), testNode(t, id, id)); err != nil {
			t.Fatal(err)
		}
	}
	a, b := new(pinnedTestProxy), new(pinnedTestProxy)
	for id, p := range map[string]*pinnedTestProxy{"a": a, "b": b} {
		if _, err := r.proxies.LoadOrCreate(t.Context(), id, func() (*ProxyEntry, error) { return &ProxyEntry{Proxy: p, Name: id}, nil }); err != nil {
			t.Fatal(err)
		}
	}
	svc := NewSelectorService(r)
	s, err := svc.Save(t.Context(), contract.Selector{Name: "Pinned", NodeID: "a"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := r.GetTarget(t.Context(), "tcp", "proxy", contractroute.Target{Type: "selector", ID: s.ID})
	if err != nil {
		t.Fatal(err)
	}
	addr, _ := netapi.ParseAddress("tcp", "example.com:443")
	conn, err := p.Conn(t.Context(), addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	s.NodeID = "b"
	if _, err := svc.Save(t.Context(), s); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 6)
	if n, err := conn.Read(buf); err != nil || n != 6 || string(buf) != "pinned" {
		t.Fatal(n, err)
	}
	if a.tcp.count != 1 || b.tcp.count != 0 {
		t.Fatal("request replayed across selector switch")
	}
}

func BenchmarkSelectorTarget(b *testing.B) {
	for _, mode := range []string{"manual", "failover", "weighted"} {
		b.Run(mode, func(b *testing.B) {
			r := NewNodeRuntime(b.TempDir() + "/state.db")
			defer r.Close()
			n := contract.Node{ID: "a", Name: "a", Enabled: true, Chain: []contract.Protocol{{Type: "direct", Direct: &contract.Direct{}}}}
			if _, err := r.Save(b.Context(), n); err != nil {
				b.Fatal(err)
			}
			r.observer.counter("a").remoteEvidence(true, contract.HealthSample{Kind: "connect", OK: true}, nil)
			s, err := NewSelectorService(r).Save(b.Context(), contract.Selector{Name: "Bench", NodeID: "a", Policy: &contract.SelectorPolicy{Mode: mode, Fallback: "priority_unknown", Candidates: []contract.SelectorCandidate{{NodeID: "a", Enabled: true, Weight: 1}}}})
			if err != nil {
				b.Fatal(err)
			}
			ctx := netapi.WithContext(b.Context())
			target := contractroute.Target{Type: "selector", ID: s.ID}
			if _, err := r.GetTarget(ctx, "tcp", "proxy", target); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, err := r.GetTarget(ctx, "tcp", "proxy", target); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestSpeedBudgetSurvivesReopenAndChargesCancelledTests(t *testing.T) {
	r := newTestRuntime(t)
	node := testNode(t, "a", "a")
	if _, err := r.Save(t.Context(), node); err != nil {
		t.Fatal(err)
	}
	// Spend the entire daily reservation through a guaranteed local refusal.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := l.Addr().String()
	_ = l.Close()
	request := contract.SpeedTestRequest{URL: "https://" + endpoint, MaxBytes: 1024, DailyBudgetBytes: 1024 + contract.SpeedTransportAllowance, TimeoutMS: 1000, DurationMS: 100}
	if _, err := r.Speed(t.Context(), node.ID, request); err == nil || errors.Is(err, errSpeedBudget) {
		t.Fatalf("first test must attempt the closed endpoint, got %v", err)
	}
	var reserved, version int64
	if err := r.sqlite.DB().QueryRowContext(t.Context(), `SELECT reserved_bytes,accounting_version FROM node_speed_budget`).Scan(&reserved, &version); err != nil || reserved != request.DailyBudgetBytes || version != 2 {
		t.Fatalf("reservation=%d version=%d err=%v", reserved, version, err)
	}
	if _, err := r.Speed(t.Context(), node.ID, request); err == nil || err.Error() != "daily speed test traffic budget exhausted" {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	r2 := NewNodeRuntime(r.path)
	defer r2.Close()
	if _, err := r2.Speed(t.Context(), node.ID, request); err == nil || err.Error() != "daily speed test traffic budget exhausted" {
		t.Fatal(err)
	}
	// The configuration export cannot reset the instance-wide traffic budget.
	data, err := storagesqlite.ExportConfig(t.Context(), r2.sqlite.DB())
	if err != nil {
		t.Fatal(err)
	}
	if err := storagesqlite.RestoreConfig(t.Context(), r2.sqlite.DB(), data); err != nil {
		t.Fatal(err)
	}
	if _, err := r2.Speed(t.Context(), node.ID, request); err == nil || err.Error() != "daily speed test traffic budget exhausted" {
		t.Fatal(err)
	}
}

func TestSpeedBudgetUpgradeRefusesLegacyUsageUntilUTCReset(t *testing.T) {
	r := newTestRuntime(t)
	n := testNode(t, "a", "a")
	if _, err := r.Save(t.Context(), n); err != nil {
		t.Fatal(err)
	}
	day := time.Now().UTC().Unix() / 86400
	if _, err := r.sqlite.DB().ExecContext(t.Context(), `INSERT INTO node_speed_budget(id,day,reserved_bytes,accounting_version) VALUES(1,?,1024,1)`, day); err != nil {
		t.Fatal(err)
	}
	req := contract.SpeedTestRequest{URL: "https://127.0.0.1:1", MaxBytes: 1024, DailyBudgetBytes: 1 << 20, DurationMS: 100, TimeoutMS: 100}
	if _, err := r.Speed(t.Context(), n.ID, req); !errors.Is(err, errSpeedBudget) {
		t.Fatal(err)
	}
	if _, ok := r.proxies.store.Load(n.ID); ok {
		t.Fatal("legacy budget rejection constructed outbound")
	}
	if _, err := r.sqlite.DB().ExecContext(t.Context(), `UPDATE node_speed_budget SET day=?`, day-1); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Speed(t.Context(), n.ID, req); err == nil || errors.Is(err, errSpeedBudget) {
		t.Fatal(err)
	}
	var version int
	var reserved int64
	if err := r.sqlite.DB().QueryRowContext(t.Context(), `SELECT accounting_version,reserved_bytes FROM node_speed_budget`).Scan(&version, &reserved); err != nil || version != 2 || reserved != req.MaxBytes+contract.SpeedTransportAllowance {
		t.Fatal(version, reserved, err)
	}
}

func TestPreferredRecoveryRuntimePersistenceAdmissionAndMetrics(t *testing.T) {
	r, saved := qualificationSelector(t, "failover")
	svc := NewSelectorService(r)
	p := saved.Policy
	p.Mode, p.PreferredID = "lowest_latency", "a"
	p.LatencyTarget, p.MinSamples = "https://probe.example/health", 1
	p.MinHoldMS, p.CooldownMS = 1, 1
	p.Circuit = &contract.CircuitConfig{Disabled: true}
	for _, id := range []string{"a", "b"} {
		rtt := 180.0
		if id == "b" {
			rtt = 100
		}
		r.observer.counter(id).remoteEvidence(true, contract.HealthSample{Kind: "https", Target: p.LatencyTarget, RTTMS: rtt, OK: true}, nil)
	}
	var err error
	saved, err = svc.Save(t.Context(), saved)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(time.Second)
	rebuild := func(at time.Time) contract.SelectorRuntimeStatus {
		t.Helper()
		r.selectors.mu.Lock()
		defer r.selectors.mu.Unlock()
		r.selectors.rebuild(at)
		return r.selectors.snapshot.Load().items[saved.ID].status
	}
	if v := rebuild(now); v.TCP.NodeID != "b" {
		t.Fatal("initial metric ranking did not select b", v)
	}
	for range 16 {
		r.observer.counter("a").remoteEvidence(true, contract.HealthSample{Kind: "https", Target: p.LatencyTarget, RTTMS: 20, OK: true}, nil)
	}
	status := rebuild(now.Add(time.Second))
	if status.TCP.NodeID != "b" || status.TCP.Reason != "preferred_return_disabled" || status.Suppressed == 0 {
		t.Fatal("runtime ignored sticky recovery policy", status)
	}
	// Admission uses that compiled decision and leaves existing runtime owners
	// intact. Neither ranking nor SQL is needed to open this fake transport.
	proxy, err := r.GetTarget(t.Context(), "tcp", "proxy", contractroute.Target{Type: "selector", ID: saved.ID})
	if err != nil {
		t.Fatal(err)
	}
	addr, _ := netapi.ParseAddress("tcp", "example.invalid:443")
	conn, err := proxy.Conn(netapi.WithContext(t.Context()), addr)
	if err != nil {
		t.Fatal(err)
	}
	if r.observer.counter("a").activeTCP.Load() != 0 || r.observer.counter("b").activeTCP.Load() != 1 {
		_ = conn.Close()
		t.Fatal("admission bypassed sticky selection")
	}
	defer conn.Close()
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(r.Metrics())
	found := false
	for _, m := range metricFamily(t, reg, "yuhaiin_outbound_selector_suppressed_total").Metric {
		for _, label := range m.Label {
			if label.GetName() == "reason" && label.GetValue() == "preferred_return_disabled" && m.GetCounter().GetValue() > 0 {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("preferred suppression missing from bounded metrics")
	}
	saved.Policy.ReturnToPreferred = true
	saved, err = svc.Save(t.Context(), saved)
	if err != nil {
		t.Fatal(err)
	}
	if v := rebuild(now.Add(2 * time.Second)); v.TCP.NodeID != "a" || v.Revision != saved.Revision {
		t.Fatal("saved return policy did not activate", v)
	}
	if r.observer.counter("b").activeTCP.Load() != 1 {
		t.Fatal("selection change replaced an established stream")
	}
	next, err := proxy.Conn(netapi.WithContext(t.Context()), addr)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if r.observer.counter("a").activeTCP.Load() != 1 || r.observer.counter("b").activeTCP.Load() != 1 {
		t.Fatal("new connection did not use the returned preferred node")
	}
	items, err := svc.List(t.Context())
	if err != nil || len(items) != 1 || !items[0].Policy.ReturnToPreferred || items[0].Policy.PreferredID != "a" {
		t.Fatal("recovery policy was not persisted", items, err)
	}
}
