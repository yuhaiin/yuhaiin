package node

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"slices"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
)

func selectionFixture(now time.Time) (contract.Selector, []selectionInput) {
	p := contract.SelectorPolicy{Mode: "lowest_latency", SpeedTarget: "https://speed.example/test"}.Effective()
	s := contract.Selector{ID: "s", NodeID: "a", Policy: &p}
	var inputs []selectionInput
	for i, id := range []string{"a", "b"} {
		c := contract.SelectorCandidate{NodeID: id, Enabled: true, Priority: i, Weight: uint32(i + 1)}
		s.Policy.Candidates = append(s.Policy.Candidates, c)
		h := contract.ChannelHealth{State: "healthy", ConsecutiveSuccesses: 3}
		for range 3 {
			h.Samples = append(h.Samples, contract.HealthSample{At: now.UnixMilli() - 100, OK: true, Kind: "https", Target: p.LatencyTarget, RTTMS: float64(100 - i*50)})
		}
		inputs = append(inputs, selectionInput{config: c, enabled: true, health: h, speed: contract.ThroughputMeasurement{At: now.UnixMilli() - 100, OK: true, Samples: 3, Target: p.SpeedTarget, DownloadMbps: float64(200 - i*100)}})
	}
	return s, inputs
}

func TestSelectionStrategiesAndManualCompatibility(t *testing.T) {
	now := time.Unix(10000, 0)
	for _, tc := range []struct{ mode, want string }{{"manual", "a"}, {"failover", "a"}, {"lowest_latency", "b"}, {"highest_throughput", "a"}, {"balanced", "b"}, {"weighted", "a"}} {
		t.Run(tc.mode, func(t *testing.T) {
			s, inputs := selectionFixture(now)
			s.Policy.Mode = tc.mode
			d := evaluateSelector(s, inputs, contract.SelectorDecision{}, now)
			if d.NodeID != tc.want {
				t.Fatalf("decision=%+v, want %s", d, tc.want)
			}
			if tc.mode == "balanced" && (d.Candidates[1].Score <= 0 || d.Candidates[1].Score > 1 || d.Candidates[1].Components == nil) {
				t.Fatalf("unexplained/unbounded score: %+v", d)
			}
		})
	}
	s, _ := selectionFixture(now)
	s.Policy = nil
	if d := evaluateSelector(s, nil, contract.SelectorDecision{}, now); d.NodeID != "a" || d.Reason != "manual" {
		t.Fatal(d)
	}
	s.Policy = &contract.SelectorPolicy{Mode: "balanced", Locked: true}
	if d := evaluateSelector(s, nil, contract.SelectorDecision{}, now); d.NodeID != "a" || d.Reason != "manual_lock" {
		t.Fatal(d)
	}
}

func TestSelectionExpiresAndNeverInventsCapacity(t *testing.T) {
	now := time.Unix(10000, 0)
	for _, tc := range []struct {
		name   string
		mutate func(*contract.Selector, []selectionInput)
	}{
		{"expired_rtt", func(s *contract.Selector, in []selectionInput) {
			for i := range in {
				for j := range in[i].health.Samples {
					in[i].health.Samples[j].At = now.Add(-3 * time.Minute).UnixMilli()
				}
			}
		}},
		{"incomparable_rtt", func(s *contract.Selector, in []selectionInput) {
			for i := range in {
				for j := range in[i].health.Samples {
					in[i].health.Samples[j].Target = "another"
				}
			}
		}},
		{"unknown_rtt", func(s *contract.Selector, in []selectionInput) {
			for i := range in {
				for j := range in[i].health.Samples {
					in[i].health.Samples[j].RTTMS = 0
				}
			}
		}},
		{"expired_speed", func(s *contract.Selector, in []selectionInput) {
			s.Policy.Mode = "highest_throughput"
			for i := range in {
				in[i].speed.At = now.Add(-3 * time.Minute).UnixMilli()
			}
		}},
		{"unknown_speed", func(s *contract.Selector, in []selectionInput) {
			s.Policy.Mode = "highest_throughput"
			for i := range in {
				in[i].speed = contract.ThroughputMeasurement{}
			}
		}},
		{"wrong_speed_target", func(s *contract.Selector, in []selectionInput) {
			s.Policy.Mode = "highest_throughput"
			s.Policy.SpeedTarget = "https://other.example"
		}},
		{"missing_upload", func(s *contract.Selector, in []selectionInput) {
			s.Policy.Mode = "balanced"
			s.Policy.Weights.Upload = 1
		}},
		{"nan_rtt", func(s *contract.Selector, in []selectionInput) {
			for i := range in {
				for j := range in[i].health.Samples {
					in[i].health.Samples[j].RTTMS = math.NaN()
				}
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, in := selectionFixture(now)
			tc.mutate(&s, in)
			d := evaluateSelector(s, in, contract.SelectorDecision{}, now)
			if d.NodeID != "" {
				t.Fatalf("invalid observations selected %q", d.NodeID)
			}
		})
	}
}

func TestLatencyHysteresisHoldAndImmediateFailure(t *testing.T) {
	now := time.Unix(10000, 0)
	s, in := selectionFixture(now)
	old := contract.SelectorDecision{NodeID: "a", Since: now.Add(-time.Hour).UnixMilli()}
	for j := range in[0].health.Samples {
		in[0].health.Samples[j].RTTMS = 52
		in[1].health.Samples[j].RTTMS = 49
	}
	for range 100 {
		d := evaluateSelector(s, in, old, now)
		if d.NodeID != "a" || d.Reason != "latency_hysteresis" {
			t.Fatal(d)
		}
		old = d
	}
	for j := range in[0].health.Samples {
		in[0].health.Samples[j].RTTMS = 180
		in[1].health.Samples[j].RTTMS = 45
	}
	d := evaluateSelector(s, in, old, now)
	if d.NodeID != "b" {
		t.Fatal(d)
	}
	old = contract.SelectorDecision{NodeID: "a", Since: now.UnixMilli()}
	if d := evaluateSelector(s, in, old, now); d.NodeID != "a" || d.Reason != "hold_or_cooldown" {
		t.Fatal(d)
	}
	in[0].health.ConsecutiveFailures = 3
	if d := evaluateSelector(s, in, old, now); d.NodeID != "b" {
		t.Fatalf("hold prevented emergency failover: %+v", d)
	}
	// Both absolute and relative improvement must be met.
	in[0].health.ConsecutiveFailures = 0
	s.Policy.MinImprovementPercent = 90
	if d := evaluateSelector(s, in, contract.SelectorDecision{NodeID: "a", Since: now.Add(-time.Hour).UnixMilli()}, now); d.NodeID != "a" {
		t.Fatal(d)
	}
}

func TestFailoverRecoveryFallbackAndNetworkSeparation(t *testing.T) {
	now := time.Unix(10000, 0)
	s, in := selectionFixture(now)
	s.Policy.Mode = "failover"
	old := contract.SelectorDecision{NodeID: "b", Since: now.Add(-time.Hour).UnixMilli()}
	if d := evaluateSelector(s, in, old, now); d.NodeID != "b" || d.Reason != "sticky_failover" {
		t.Fatal(d)
	}
	s.Policy.ReturnToPreferred = true
	if d := evaluateSelector(s, in, old, now); d.NodeID != "a" {
		t.Fatal(d)
	}
	in[0].health = contract.ChannelHealth{}
	if d := evaluateSelector(s, in, old, now); d.NodeID != "b" {
		t.Fatal(d)
	}
	in[1].health = contract.ChannelHealth{}
	if d := evaluateSelector(s, in, old, now); d.NodeID != "" {
		t.Fatal(d)
	}
	s.Policy.Fallback = "priority_unknown"
	if d := evaluateSelector(s, in, old, now); d.NodeID != "a" {
		t.Fatal(d)
	}
	in[0].enabled = false
	if d := evaluateSelector(s, in, old, now); d.NodeID != "b" {
		t.Fatal(d)
	}
	s.Policy.Fallback = "selected"
	if d := evaluateSelector(s, in, old, now); d.NodeID != "" {
		t.Fatal("fallback resurrected disabled node", d)
	}
	// TCP evidence must not manufacture UDP reachability.
	s, in = selectionFixture(now)
	s.Policy.Mode = "failover"
	udp := slices.Clone(in)
	for i := range udp {
		udp[i].udp = true
		udp[i].health = contract.ChannelHealth{}
	}
	if d := evaluateSelector(s, udp, old, now); d.NodeID != "" {
		t.Fatal(d)
	}
}

func TestWeightedDistributionAndDisabledCandidates(t *testing.T) {
	now := time.Unix(10000, 0)
	s, in := selectionFixture(now)
	s.Policy.Mode = "weighted"
	d := evaluateSelector(s, in, contract.SelectorDecision{}, now)
	w, total := compileWeights(in, d.Candidates)
	counts := make([]int, 2)
	for ticket := range total {
		counts[pickWeighted(w, ticket)]++
	}
	if total != 3 || counts[0] != 1 || counts[1] != 2 {
		t.Fatal(total, counts)
	}
	in[1].enabled = false
	d = evaluateSelector(s, in, contract.SelectorDecision{}, now)
	w, total = compileWeights(in, d.Candidates)
	if total != 1 || pickWeighted(w, 0) != 0 {
		t.Fatal(total, w)
	}
}

func TestRemoteEvidenceIgnoresCancellationAndUDPConstruction(t *testing.T) {
	c := new(nodeCounters)
	for _, err := range []error{context.Canceled, net.ErrClosed, errors.New("quota denied"), errors.New("access policy denied")} {
		c.remoteEvidence(true, contract.HealthSample{}, err)
	}
	c.remoteEvidence(true, contract.HealthSample{}, &net.OpError{Op: "block", Net: "tcp", Err: errors.New("policy")})
	if v := c.snapshot(); len(v.TCPHealth.Samples) != 0 {
		t.Fatal(v)
	}
	for range 3 {
		c.remoteEvidence(true, contract.HealthSample{}, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("unreachable")})
	}
	if v := c.snapshot(); v.TCPHealth.State != "unhealthy" || len(v.UDPHealth.Samples) != 0 {
		t.Fatal(v)
	}
	for range 2 {
		c.remoteEvidence(true, contract.HealthSample{OK: true, Kind: "connect"}, nil)
	}
	if v := c.snapshot(); v.TCPHealth.State != "healthy" {
		t.Fatal(v)
	}
	for range 100 {
		c.remoteEvidence(true, contract.HealthSample{OK: true}, nil)
	}
	if v := c.snapshot(); len(v.TCPHealth.Samples) != 64 {
		t.Fatal(len(v.TCPHealth.Samples))
	}
}

func TestBusinessConnectionChurnDoesNotEvictLatencySamples(t *testing.T) {
	now := time.Now()
	s, in := selectionFixture(now)
	c := new(nodeCounters)
	for _, sample := range in[0].health.Samples {
		c.remoteEvidence(true, sample, nil)
	}
	for range 1000 {
		c.remoteEvidence(true, contract.HealthSample{At: now.UnixMilli(), Kind: "connect", OK: true}, nil)
	}
	in[0].health = c.snapshot().TCPHealth
	if status := scoreCandidate(s.Policy.Effective(), in[0], now); !status.Eligible || status.Samples != 3 || status.RTTMS != 100 {
		t.Fatal(status)
	}
}

func BenchmarkSelectorRanking(b *testing.B) {
	for _, size := range []int{100, 1000} {
		for _, mode := range []string{"failover", "lowest_latency", "highest_throughput", "balanced"} {
			b.Run(fmt.Sprintf("%s/%d", mode, size), func(b *testing.B) {
				now := time.Unix(10000, 0)
				s, pair := selectionFixture(now)
				s.Policy.Mode = mode
				inputs := make([]selectionInput, size)
				for i := range inputs {
					inputs[i] = pair[i%2]
					inputs[i].config.NodeID = fmt.Sprint(i)
				}
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					evaluateSelector(s, inputs, contract.SelectorDecision{}, now)
				}
			})
		}
	}
}
