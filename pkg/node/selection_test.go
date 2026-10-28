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

func TestLatencyAlternatingWinnerDoesNotFlapAndAllowsSustainedImprovement(t *testing.T) {
	now := time.Unix(10000, 0)
	selector, inputs := selectionFixture(now)
	previous := contract.SelectorDecision{NodeID: "a", Since: now.Add(-time.Hour).UnixMilli()}
	update := func(first, second float64) {
		for index, rtt := range []float64{first, second} {
			for sample := range inputs[index].health.Samples {
				inputs[index].health.Samples[sample].RTTMS = rtt
				inputs[index].health.Samples[sample].At = now.UnixMilli()
			}
		}
	}
	for index := range 100 {
		now = now.Add(time.Second)
		if index%2 == 0 {
			update(52, 49)
		} else {
			update(49, 52)
		}
		previous = evaluateSelector(selector, inputs, previous, now)
		if previous.NodeID != "a" {
			t.Fatal("small alternating RTT changes moved the outbound", index, previous)
		}
	}
	update(180, 45)
	previous = evaluateSelector(selector, inputs, previous, now)
	if previous.NodeID != "b" {
		t.Fatal("hysteresis prevented a large sustained improvement", previous)
	}
	// The newly selected node also stays pinned during the configured hold.
	now = now.Add(time.Second)
	update(20, 45)
	if decision := evaluateSelector(selector, inputs, previous, now); decision.NodeID != "b" || decision.Reason != "hold_or_cooldown" {
		t.Fatal("a reverse improvement bypassed the hold", decision)
	}
}

func TestTimeoutRateUsesFreshHealthOutcomesWithoutDoubleCountingReplies(t *testing.T) {
	now := time.Unix(10000, 0)
	selector, inputs := selectionFixture(now)
	input := inputs[0]
	input.health.Samples = append(input.health.Samples,
		contract.HealthSample{At: now.UnixMilli(), Kind: "https", Timeout: true},
		contract.HealthSample{At: now.UnixMilli(), Kind: "connect"},
		contract.HealthSample{At: now.UnixMilli(), Kind: "response", OK: true},
		contract.HealthSample{At: now.Add(-time.Hour).UnixMilli(), Kind: "https", Timeout: true},
		contract.HealthSample{At: now.Add(time.Minute).UnixMilli(), Kind: "https", Timeout: true})
	status := scoreCandidate(selector.Policy.Effective(), input, now)
	if status.HealthSamples != 5 || status.FailureRate != .4 || status.TimeoutRate != .2 || status.Samples != 3 {
		t.Fatal("health timeout denominator mixed stale/duplicate/RTT samples", status)
	}
	status = scoreCandidate(selector.Policy.Effective(), input, now.Add(time.Hour))
	if status.HealthSamples != 0 || status.TimeoutRate != 0 || status.FailureRate != 0 || status.Eligible {
		t.Fatal("expired timeout evidence survived", status)
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

// A recovered preferred Node remains subject to the active metric policy.
// Sticky return must not pin an unusable survivor or block a third alternative.
func TestPreferredRecoveryAcrossMetricPolicies(t *testing.T) {
	now := time.Unix(10000, 0)
	for _, mode := range []string{"lowest_latency", "highest_throughput", "balanced"} {
		t.Run(mode, func(t *testing.T) {
			s, inputs := selectionFixture(now)
			s.Policy.Mode, s.Policy.PreferredID = mode, "a"
			s.Policy.Weights = contract.SelectorWeights{RTT: 1, Download: 1}
			for i := range inputs[0].health.Samples {
				inputs[0].health.Samples[i].RTTMS = 20
				inputs[1].health.Samples[i].RTTMS = 180
			}
			old := contract.SelectorDecision{NodeID: "b", Since: now.Add(-time.Hour).UnixMilli()}
			if d := evaluateSelector(s, inputs, old, now); d.NodeID != "b" || d.Reason != "preferred_return_disabled" || d.Since != old.Since {
				t.Fatal("return-disabled policy did not retain healthy survivor", d)
			}
			s.Policy.ReturnToPreferred = true
			if d := evaluateSelector(s, inputs, old, now); d.NodeID != "a" {
				t.Fatal("qualified preferred did not return", d)
			}
			old.Since = now.UnixMilli()
			if d := evaluateSelector(s, inputs, old, now); d.NodeID != "b" || d.Reason != "hold_or_cooldown" {
				t.Fatal("preferred bypassed hold", d)
			}
			old.Since = now.Add(-time.Hour).UnixMilli()
			for i := range inputs[0].health.Samples {
				inputs[0].health.Samples[i].RTTMS = 180
				inputs[1].health.Samples[i].RTTMS = 20
			}
			inputs[0].speed.DownloadMbps = 10
			if d := evaluateSelector(s, inputs, old, now); d.NodeID != "b" {
				t.Fatal("preferred overrode better metric", d)
			}
			// Failure overrides return suppression and hold, including expiry.
			s.Policy.ReturnToPreferred = false
			inputs[0], inputs[1] = inputs[1], inputs[0]
			inputs[0].config.NodeID, inputs[1].config.NodeID = "a", "b"
			inputs[1].health = contract.ChannelHealth{}
			inputs[1].speed = contract.ThroughputMeasurement{}
			old.Since = now.UnixMilli()
			if d := evaluateSelector(s, inputs, old, now); d.NodeID != "a" {
				t.Fatal("return suppression prevented emergency failover", d)
			}
			if d := evaluateSelector(s, inputs, contract.SelectorDecision{}, now); d.NodeID != "a" {
				t.Fatal("initial selection suppressed preferred", d)
			}
		})
	}
}

func TestPreferredReturnRequiresFreshImprovementAndSeparateUDP(t *testing.T) {
	now := time.Unix(10000, 0)
	for _, mode := range []string{"lowest_latency", "highest_throughput", "balanced"} {
		t.Run(mode, func(t *testing.T) {
			s, inputs := selectionFixture(now)
			s.Policy.Mode, s.Policy.PreferredID, s.Policy.ReturnToPreferred = mode, "a", true
			s.Policy.Weights = contract.SelectorWeights{RTT: 1}
			for i := range inputs[0].health.Samples {
				inputs[0].health.Samples[i].RTTMS = 49
				inputs[1].health.Samples[i].RTTMS = 52
			}
			inputs[0].speed.DownloadMbps, inputs[1].speed.DownloadMbps = 105, 100
			old := contract.SelectorDecision{NodeID: "b", Since: now.Add(-time.Hour).UnixMilli()}
			want := map[string]string{"lowest_latency": "latency_hysteresis", "highest_throughput": "throughput_hysteresis", "balanced": "score_hysteresis"}[mode]
			if d := evaluateSelector(s, inputs, old, now); d.NodeID != "b" || d.Reason != want {
				t.Fatal("preferred bypassed improvement threshold", d)
			}
			for i := range inputs[0].health.Samples {
				inputs[0].health.Samples[i].At = now.Add(-3 * time.Minute).UnixMilli()
			}
			inputs[0].speed.At = now.Add(-3 * time.Minute).UnixMilli()
			if d := evaluateSelector(s, inputs, old, now); d.NodeID != "b" || d.Candidates[0].Eligible {
				t.Fatal("expired preferred was ranked", d)
			}
		})
	}
	s, inputs := selectionFixture(now)
	s.Policy.PreferredID = "b"
	for i := range inputs {
		inputs[i].udp = true
		for j := range inputs[i].health.Samples {
			inputs[i].health.Samples[j].Kind = "dns"
			inputs[i].health.Samples[j].Target = s.Policy.UDPLatencyTarget
		}
	}
	old := contract.SelectorDecision{NodeID: "a", Since: now.Add(-time.Hour).UnixMilli()}
	if d := evaluateSelector(s, inputs, old, now); d.NodeID != "a" || d.Reason != "preferred_return_disabled" {
		t.Fatal("UDP ignored its return policy", d)
	}
	s.Policy.ReturnToPreferred = true
	if d := evaluateSelector(s, inputs, old, now); d.NodeID != "b" {
		t.Fatal("UDP preferred did not return with fresh DNS evidence", d)
	}
}

func TestPreferredRecoveryKeepsOtherCandidatesRanked(t *testing.T) {
	now := time.Unix(10000, 0)
	s, inputs := selectionFixture(now)
	s.Policy.PreferredID = "b"
	third := inputs[1]
	third.config.NodeID = "c"
	third.health.Samples = slices.Clone(third.health.Samples)
	for i := range third.health.Samples {
		third.health.Samples[i].RTTMS = 60
	}
	inputs = append(inputs, third)
	old := contract.SelectorDecision{NodeID: "a", Since: now.Add(-time.Hour).UnixMilli()}
	if d := evaluateSelector(s, inputs, old, now); d.NodeID != "c" {
		t.Fatal("sticky preferred blocked a better non-preferred alternative", d)
	}
	s.Policy.Mode = "failover"
	// A configured preference also controls initial main selection. The return
	// switch only controls whether to leave an eligible survivor later.
	if d := evaluateSelector(s, inputs, contract.SelectorDecision{}, now); d.NodeID != "b" {
		t.Fatal("initial failover preference ignored", d)
	}
	if d := evaluateSelector(s, inputs, old, now); d.NodeID != "a" || d.Reason != "sticky_failover" {
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

func TestSelectedFallbackCannotResurrectOpenCircuit(t *testing.T) {
	now := time.Unix(10000, 0)
	s, in := selectionFixture(now)
	s.Policy.Mode = "failover"
	s.Policy.Fallback = "selected"
	for i := range in {
		in[i].health = contract.ChannelHealth{}
		in[i].circuit = &contract.CircuitStatus{State: "open"}
	}
	if d := evaluateSelector(s, in, contract.SelectorDecision{}, now); d.NodeID != "" {
		t.Fatal("open fallback advertised as selected", d)
	}
	s.Policy.Locked = true
	if d := evaluateSelector(s, in, contract.SelectorDecision{}, now); d.NodeID != "a" || d.Reason != "manual_lock" {
		t.Fatal("explicit manual lock changed", d)
	}
}

func BenchmarkSelectorPreferredRecoveryRanking(b *testing.B) {
	for _, size := range []int{100, 1000} {
		for _, mode := range []string{"lowest_latency", "highest_throughput", "balanced"} {
			for _, returning := range []bool{false, true} {
				b.Run(fmt.Sprintf("%s/%d/return=%t", mode, size, returning), func(b *testing.B) {
					now := time.Unix(10000, 0)
					s, pair := selectionFixture(now)
					s.Policy.Mode, s.Policy.PreferredID, s.Policy.ReturnToPreferred = mode, "0", returning
					inputs := make([]selectionInput, size)
					for i := range inputs {
						inputs[i] = pair[min(i, 1)]
						inputs[i].config.NodeID = fmt.Sprint(i)
						inputs[i].health.Samples = slices.Clone(inputs[i].health.Samples)
						for j := range inputs[i].health.Samples {
							inputs[i].health.Samples[j].RTTMS = float64(20 + min(i, 1)*100)
						}
					}
					old := contract.SelectorDecision{NodeID: "1", Since: now.Add(-time.Hour).UnixMilli()}
					b.ReportAllocs()
					b.ResetTimer()
					for b.Loop() {
						evaluateSelector(s, inputs, old, now)
					}
				})
			}
		}
	}
}
