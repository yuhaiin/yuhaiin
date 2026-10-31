package node

import (
	"fmt"
	"io"
	"net"
	"runtime"
	"syscall"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	"github.com/Asutorufa/yuhaiin/pkg/store"
)

// These metrics describe Go heap and process goroutines, not RSS or real VPN
// sessions. Run with -benchtime=1x: the operation includes fixture creation,
// full histories, snapshot churn, 1,024 retained fake TCP/UDP pairs and cleanup.
func BenchmarkSelectorRuntimeResources(b *testing.B) {
	for _, count := range []int{100, 1000} {
		for _, shared := range []int{1, 10} {
			b.Run(fmt.Sprintf("%d/%d-selectors", count, shared), func(b *testing.B) {
				for b.Loop() {
					path := b.TempDir() + "/state.db"
					seedResourceDeployment(b, path, count, shared)
					before := nodeResourceFootprint()
					live, active := resourceRuntimeCycle(b, path, count)
					closed := nodeResourceFootprint()
					b.ReportMetric(float64(int64(live.heap)-int64(before.heap)), "live-heap-delta-B")
					b.ReportMetric(float64(live.goroutines-before.goroutines), "live-extra-goroutines")
					b.ReportMetric(float64(int64(active.heap)-int64(live.heap)), "active-flow-heap-delta-B")
					b.ReportMetric(float64(active.goroutines-live.goroutines), "active-extra-goroutines")
					b.ReportMetric(float64(int64(closed.heap)-int64(before.heap)), "closed-heap-delta-B")
					b.ReportMetric(float64(closed.goroutines-before.goroutines), "closed-goroutine-delta")
				}
			})
		}
	}
}

type nodeResourceUsage struct {
	heap       uint64
	goroutines int
}

func nodeResourceFootprint() nodeResourceUsage {
	runtime.GC()
	runtime.GC()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return nodeResourceUsage{heap: stats.HeapAlloc, goroutines: runtime.NumGoroutine()}
}

func seedResourceDeployment(b *testing.B, path string, count, shared int) {
	b.Helper()
	db, err := sqlite.Open(b.Context(), path)
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	nodes := make([]contract.Node, count)
	candidates := make([]contract.SelectorCandidate, count)
	for i := range nodes {
		id := fmt.Sprintf("resource-%04d", i)
		nodes[i] = contract.Node{ID: id, Name: id, Group: "resource", Origin: "remote", Enabled: true, Chain: []contract.Protocol{{Type: "direct", Direct: &contract.Direct{}}}}
		candidates[i] = contract.SelectorCandidate{NodeID: id, Enabled: true, Priority: i, Weight: 1}
	}
	if err := store.NewNodeStore(db.DB()).ReplaceRemote(b.Context(), "resource", nodes, time.Now().Unix()); err != nil {
		b.Fatal(err)
	}
	for i := range shared {
		id := "resource"
		if i > 0 {
			id = fmt.Sprintf("resource-%d", i)
		}
		_, err = store.NewSelectorStore(db.DB()).Save(b.Context(), contract.Selector{ID: id, Name: "Resource qualification", NodeID: nodes[0].ID, Policy: &contract.SelectorPolicy{
			Mode: "balanced", PreferredID: nodes[0].ID, Candidates: candidates,
			Weights: contract.SelectorWeights{RTT: 1}, MaxFailureRate: .95, Circuit: &contract.CircuitConfig{Disabled: true},
		}})
		if err != nil {
			b.Fatal(err)
		}
	}
}

func resourceRuntimeCycle(b *testing.B, path string, count int) (live, active nodeResourceUsage) {
	b.Helper()
	r := NewNodeRuntime(path)
	defer func() {
		if err := r.Close(); err != nil {
			b.Error(err)
		}
	}()
	if _, err := r.openNodes(b.Context()); err != nil {
		b.Fatal(err)
	}
	p := contract.SelectorPolicy{}.Effective()
	for i := range count {
		id := fmt.Sprintf("resource-%04d", i)
		if _, err := r.proxies.LoadOrCreate(b.Context(), id, func() (*ProxyEntry, error) {
			return &ProxyEntry{Proxy: qualificationProxy{}, Name: id}, nil
		}); err != nil {
			b.Fatal(err)
		}
		for range 64 {
			r.observer.counter(id).remoteEvidence(true, contract.HealthSample{Kind: "https", Target: p.LatencyTarget, RTTMS: float64(i + 1), OK: true}, nil)
			r.observer.counter(id).remoteEvidence(false, contract.HealthSample{Kind: "dns", Target: p.UDPLatencyTarget, RTTMS: float64(i + 1), OK: true}, nil)
		}
	}
	// Fifty failure/recovery cycles publish 100 complete snapshots. This is
	// real Closed-health FSM churn, not only different positive RTT samples.
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
	for i := range 50 {
		id := fmt.Sprintf("resource-%04d", i%count)
		c := r.observer.counter(id)
		for range 3 {
			c.remoteEvidence(true, contract.HealthSample{Kind: "https", Target: p.LatencyTarget}, refused)
		}
		if c.snapshot().TCPHealth.State != "unhealthy" {
			b.Fatal("failure churn did not become unhealthy")
		}
		r.selectors.mu.Lock()
		r.selectors.rebuild(time.Now())
		r.selectors.mu.Unlock()
		for range 3 {
			c.remoteEvidence(true, contract.HealthSample{Kind: "https", Target: p.LatencyTarget, RTTMS: 50, OK: true}, nil)
		}
		if c.snapshot().TCPHealth.State != "healthy" {
			b.Fatal("recovery churn did not become healthy")
		}
		r.selectors.mu.Lock()
		r.selectors.rebuild(time.Now())
		r.selectors.mu.Unlock()
	}
	live = nodeResourceFootprint()
	proxy, err := r.GetTarget(b.Context(), "tcp", "proxy", contractroute.Target{Type: "selector", ID: "resource"})
	if err != nil {
		b.Fatal(err)
	}
	addr, _ := netapi.ParseAddress("tcp", "resource.invalid:443")
	flows := make([]io.Closer, 0, 2048)
	defer func() {
		for _, flow := range flows {
			_ = flow.Close()
		}
	}()
	for range 1024 {
		ctx := netapi.WithContext(b.Context())
		conn, err := proxy.Conn(ctx, addr)
		if err != nil {
			b.Fatal(err)
		}
		flows = append(flows, conn)
		packet, err := proxy.PacketConn(ctx, addr)
		if err != nil {
			b.Fatal(err)
		}
		flows = append(flows, packet)
	}
	active = nodeResourceFootprint()
	runtime.KeepAlive(r)
	runtime.KeepAlive(flows)
	return live, active
}
