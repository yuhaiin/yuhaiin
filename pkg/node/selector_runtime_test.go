package node

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

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
	request := contract.SpeedTestRequest{URL: "https://" + endpoint, MaxBytes: 1024, DailyBudgetBytes: 1024, TimeoutMS: 1000, DurationMS: 100}
	_, _ = r.Speed(t.Context(), node.ID, request)
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
