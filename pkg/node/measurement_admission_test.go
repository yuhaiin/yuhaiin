package node

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

// A single lease budget spans manual probes, periodic probes and speed tests.
// Rejected calls must neither construct the outbound nor spend the daily budget.
func TestMeasurementAdmissionSharedByAllEntryPoints(t *testing.T) {
	r := newTestRuntime(t)
	n := testNode(t, "a", "a")
	if _, err := r.Save(t.Context(), n); err != nil {
		t.Fatal(err)
	}
	r.measurementLimit.Store(1)
	lease, err := r.admitMeasurement(t.Context(), n.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.release()
	req := contract.LatencyRequest{Type: "tcp_connect", Host: "127.0.0.1:1"}
	if _, err := r.Latency(t.Context(), n.ID, req); !errors.Is(err, errMeasurementBusy) {
		t.Fatal(err)
	}
	if err := r.selectors.runProbe(t.Context(), n, contract.ProbeSchedule{}.Effective(), req); !errors.Is(err, errProbeSkipped) {
		t.Fatal(err)
	}
	if _, err := r.Speed(t.Context(), n.ID, contract.SpeedTestRequest{URL: "https://example.invalid"}); !errors.Is(err, errMeasurementBusy) {
		t.Fatal(err)
	}
	if _, ok := r.proxies.store.Load(n.ID); ok {
		t.Fatal("rejected test constructed outbound")
	}
	var count int
	if err := r.sqlite.DB().QueryRowContext(t.Context(), `SELECT count(*) FROM node_speed_budget`).Scan(&count); err != nil || count != 0 {
		t.Fatal(count, err)
	}
	// Cancellation keeps the slot occupied until the owner actually exits.
	r.cancelMeasurements(n.ID)
	if lease.ctx.Err() != context.Canceled {
		t.Fatal("lease not cancelled")
	}
	if _, err := r.admitMeasurement(t.Context(), n.ID); !errors.Is(err, errMeasurementBusy) {
		t.Fatal(err)
	}
	lease.release()
	lease.release()
	if r.measurementActive.Load() != 0 {
		t.Fatal("double release changed active count")
	}
	r.cancelMeasurements("")
	next, err := r.admitMeasurement(t.Context(), n.ID)
	if err != nil {
		t.Fatal(err)
	}
	next.release()
}

func TestMeasurementConcurrentAdmissionAndLimitReduction(t *testing.T) {
	r := NewNodeRuntime(t.TempDir() + "/unused.db")
	defer r.Close()
	r.measurementLimit.Store(4)
	var wg sync.WaitGroup
	leases := make(chan *measurementLease, 1000)
	for range 1000 {
		wg.Go(func() {
			l, err := r.admitMeasurement(t.Context(), "a")
			if err == nil {
				leases <- l
			} else if !errors.Is(err, errMeasurementBusy) {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	close(leases)
	if len(leases) != 4 || r.measurementActive.Load() != 4 {
		t.Fatal(len(leases), r.measurementActive.Load())
	}
	r.measurementLimit.Store(1)
	for l := range leases {
		if _, err := r.admitMeasurement(t.Context(), "b"); !errors.Is(err, errMeasurementBusy) {
			t.Error(err)
		}
		l.release()
	}
	l, err := r.admitMeasurement(t.Context(), "b")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if l.ctx.Err() != context.Canceled {
		t.Fatal("shutdown did not cancel measurement")
	}
	l.release()
	if _, err := r.admitMeasurement(t.Context(), "b"); err == nil {
		t.Fatal("closed runtime admitted work")
	}
}

type waitingMeasurementProxy struct {
	netapi.Proxy
	started chan struct{}
}

func (p *waitingMeasurementProxy) Close() error { return nil }
func (p *waitingMeasurementProxy) Conn(ctx context.Context, _ netapi.Address) (net.Conn, error) {
	close(p.started)
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestNodeDisableCancelsActualManualProbe(t *testing.T) {
	r := newTestRuntime(t)
	n := testNode(t, "a", "a")
	if _, err := r.Save(t.Context(), n); err != nil {
		t.Fatal(err)
	}
	p := &waitingMeasurementProxy{started: make(chan struct{})}
	if _, err := r.proxies.LoadOrCreate(t.Context(), n.ID, func() (*ProxyEntry, error) { return &ProxyEntry{Proxy: p}, nil }); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := r.Latency(t.Context(), n.ID, contract.LatencyRequest{Type: "tcp_connect", Host: "127.0.0.1:1"})
		done <- err
	}()
	select {
	case <-p.started:
	case <-time.After(time.Second):
		t.Fatal("probe never started")
	}
	n.Enabled = false
	if _, err := r.Save(t.Context(), n); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("disable failed to cancel probe")
	}
	if r.measurementActive.Load() != 0 {
		t.Fatal("probe leaked admission slot")
	}
}

func TestMeasurementCancellationFollowsNodeLifecycle(t *testing.T) {
	for _, action := range []string{"rename", "remove", "close_node", "credential"} {
		t.Run(action, func(t *testing.T) {
			r := newTestRuntime(t)
			n := testNode(t, "a", "a")
			if action == "credential" {
				n.Chain = []contract.Protocol{{Type: "http", CredentialRef: "ref", HTTP: &contract.HTTP{}}}
			}
			if _, err := r.Save(t.Context(), n); err != nil {
				t.Fatal(err)
			}
			lease, err := r.admitMeasurement(t.Context(), n.ID)
			if err != nil {
				t.Fatal(err)
			}
			defer lease.release()
			switch action {
			case "rename":
				n.Name = "metadata only"
				_, err = r.Save(t.Context(), n)
			case "remove":
				err = r.Remove(t.Context(), n.ID)
			case "close_node":
				err = r.CloseNode(t.Context(), n.ID)
			case "credential":
				r.InvalidateCredential("ref")
			}
			if err != nil {
				t.Fatal(err)
			}
			if action == "rename" {
				if lease.ctx.Err() != nil {
					t.Fatal("metadata edit cancelled measurement")
				}
			} else if lease.ctx.Err() != context.Canceled {
				t.Fatal("node lifecycle did not cancel measurement")
			}
		})
	}
}

func TestCancelledSpeedRetainsInclusiveDurableReservation(t *testing.T) {
	r := newTestRuntime(t)
	n := testNode(t, "a", "a")
	if _, err := r.Save(t.Context(), n); err != nil {
		t.Fatal(err)
	}
	p := &waitingMeasurementProxy{started: make(chan struct{})}
	if _, err := r.proxies.LoadOrCreate(t.Context(), n.ID, func() (*ProxyEntry, error) { return &ProxyEntry{Proxy: p}, nil }); err != nil {
		t.Fatal(err)
	}
	req := contract.SpeedTestRequest{URL: "https://example.invalid/test", MaxBytes: 1024, DailyBudgetBytes: 1024 + contract.SpeedTransportAllowance, DurationMS: 100, TimeoutMS: 1000}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := r.Speed(ctx, n.ID, req); done <- err }()
	select {
	case <-p.started:
	case <-time.After(2 * time.Second):
		t.Fatal("speed test never reached actual candidate")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("speed test ignored cancellation")
	}
	var reserved int64
	if err := r.sqlite.DB().QueryRowContext(t.Context(), `SELECT reserved_bytes FROM node_speed_budget`).Scan(&reserved); err != nil || reserved != req.DailyBudgetBytes {
		t.Fatal(reserved, err)
	}
	if r.measurementActive.Load() != 0 || len(r.speedSlots) != 0 {
		t.Fatal("cancelled test leaked concurrency slot")
	}
	if _, err := r.Speed(t.Context(), n.ID, req); !errors.Is(err, errSpeedBudget) {
		t.Fatal(err)
	}
}
