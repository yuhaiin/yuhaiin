package node

import (
	"context"
	"errors"
	"net"
	"net/url"
	"sync/atomic"
	"testing"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol"
)

func TestProbeReadinessBlocksConstructionAndSpeedBudget(t *testing.T) {
	r := NewNodeRuntime(t.TempDir()+"/state.db", RequireProbePolicy())
	defer r.Close()
	if _, err := r.Save(t.Context(), testNode(t, "a", "a")); err != nil {
		t.Fatal(err)
	}
	var ready atomic.Bool
	r.SetProbePolicy(ProbePolicy{Ready: ready.Load, Wrap: func(_ context.Context, p netapi.Proxy) netapi.Proxy { return p }})
	request := contract.LatencyRequest{Type: "tcp_connect", Host: "127.0.0.1:1"}
	if _, err := r.Latency(t.Context(), "a", request); !errors.Is(err, errProbePolicyUnavailable) {
		t.Fatal(err)
	}
	if _, err := r.Speed(t.Context(), "a", contract.SpeedTestRequest{URL: "https://example.invalid"}); !errors.Is(err, errProbePolicyUnavailable) {
		t.Fatal(err)
	}
	if _, ok := r.proxies.store.Load("a"); ok {
		t.Fatal("unready policy constructed an outbound")
	}
	var reserved int
	if err := r.sqlite.DB().QueryRowContext(t.Context(), `SELECT count(*) FROM node_speed_budget`).Scan(&reserved); err != nil || reserved != 0 {
		t.Fatal("unready policy spent speed budget", reserved, err)
	}
	ready.Store(true)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := r.Latency(ctx, "a", request); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, ok := r.proxies.store.Load("a"); ok {
		t.Fatal("cancelled probe constructed an outbound")
	}
	if state := r.observer.counter("a").status("a").State; state != "unknown" {
		t.Fatal("local readiness/cancellation degraded node", state)
	}
}
func TestLocalPolicyOutcomeCannotTripNodeCircuit(t *testing.T) {
	err := &url.Error{Op: "Get", URL: "https://probe.example.invalid", Err: errors.Join(trafficcontrol.ErrLocalLimit, context.DeadlineExceeded)}
	if healthFailure(err) || circuitIOFailure(err) {
		t.Fatal("local pacing timeout marked remote failure")
	}
	c := new(nodeCounters)
	c.remoteEvidence(true, contract.HealthSample{Kind: "https"}, err)
	if len(c.snapshot().TCPHealth.Samples) != 0 {
		t.Fatal("policy timeout polluted remote health")
	}
}

func TestActiveProbeCountsOneCompleteOutcome(t *testing.T) {
	r := newTestRuntime(t)
	if _, err := r.Save(t.Context(), testNode(t, "a", "a")); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	request := contract.LatencyRequest{Type: "tcp_connect", Host: listener.Addr().String()}
	for i := range 2 {
		result, err := r.Latency(t.Context(), "a", request)
		if err != nil || !result.OK {
			t.Fatal(result, err)
		}
		h := r.observer.counter("a").snapshot().TCPHealth
		if len(h.Samples) != i+1 || h.ConsecutiveSuccesses != i+1 {
			t.Fatal("primitive connect counted as a second probe", h)
		}
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Latency(t.Context(), "a", request); err == nil {
		t.Fatal("closed test endpoint accepted a probe")
	}
	h := r.observer.counter("a").snapshot().TCPHealth
	if len(h.Samples) != 3 || h.ConsecutiveFailures != 1 {
		t.Fatal("connection failure counted twice", h)
	}
}
