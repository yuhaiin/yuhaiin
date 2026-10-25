package node

import (
	"cmp"
	"math"
	"slices"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
)

type selectionInput struct {
	circuit *contract.CircuitStatus
	udp     bool
	config  contract.SelectorCandidate
	enabled bool
	health  contract.ChannelHealth
	speed   contract.ThroughputMeasurement
	active  int64
}

// evaluateSelector runs only when producing a new immutable runtime snapshot.
// It never probes, dials, queries SQLite, or mutates observations.
func evaluateSelector(selector contract.Selector, inputs []selectionInput, previous contract.SelectorDecision, now time.Time) contract.SelectorDecision {
	p := contract.SelectorPolicy{}.Effective()
	if selector.Policy != nil {
		p = selector.Policy.Effective()
	}
	d := contract.SelectorDecision{Since: now.UnixMilli(), Candidates: make([]contract.SelectorCandidateStatus, 0, len(inputs))}
	if p.Mode == "manual" || p.Locked {
		d.NodeID, d.Reason = selector.NodeID, "manual"
		if p.Locked {
			d.Reason = "manual_lock"
		}
		if previous.NodeID == d.NodeID {
			d.Since = previous.Since
		}
		return d
	}
	best, current := -1, -1
	for i, in := range inputs {
		c := scoreCandidate(p, in, now)
		d.Candidates = append(d.Candidates, c)
		if c.Eligible {
			if in.config.NodeID == previous.NodeID {
				current = i
			}
			if best == -1 || betterCandidate(p, in.config, c, inputs[best].config, d.Candidates[best]) {
				best = i
			}
		}
	}
	if best == -1 {
		d.Reason = "no_healthy_candidate"
		if p.Fallback == "selected" {
			// Explicit last resort. Never resurrect a disabled node/candidate.
			for i, in := range inputs {
				if in.config.NodeID == selector.NodeID && in.enabled && in.config.Enabled {
					best = i
					d.Reason = "fallback_selected"
					break
				}
			}
		} else if p.Fallback == "priority_unknown" {
			for i, in := range inputs {
				c := d.Candidates[i]
				if c.State == "unknown" && in.enabled && in.config.Enabled && (p.Mode != "weighted" || in.config.Weight > 0) && (best == -1 || priorityLess(in.config, inputs[best].config)) {
					best = i
					d.Reason = "fallback_unknown"
				}
			}
		}
		if best == -1 {
			return d
		}
	}
	if d.Reason == "" {
		d.Reason = p.Mode
	}
	if current >= 0 && current != best && p.Mode != "weighted" {
		suppress := ""
		if previous.Since > 0 && now.UnixMilli()-previous.Since < max(p.MinHoldMS, p.CooldownMS) {
			suppress = "hold_or_cooldown"
		}
		old, next := d.Candidates[current], d.Candidates[best]
		switch p.Mode {
		case "lowest_latency":
			improvement := old.RTTMS - next.RTTMS
			if improvement < p.MinImprovementMS || improvement < old.RTTMS*p.MinImprovementPercent/100 {
				suppress = "latency_hysteresis"
			}
		case "balanced":
			if next.Score-old.Score < p.MinScoreImprovement {
				suppress = "score_hysteresis"
			}
		case "highest_throughput":
			if next.DownloadMbps-old.DownloadMbps < old.DownloadMbps*p.MinImprovementPercent/100 {
				suppress = "throughput_hysteresis"
			}
		}
		// Sticky recovery is distinct from metric hysteresis: administrators may
		// permit switching to a recovered preferred node or retain the survivor.
		if p.Mode == "failover" && !p.ReturnToPreferred {
			suppress = "sticky_failover"
		}
		if suppress != "" {
			best, d.Reason = current, suppress
		}
	}
	d.NodeID = inputs[best].config.NodeID
	if d.NodeID == previous.NodeID {
		d.Since = previous.Since
	}
	return d
}

func priorityLess(a, b contract.SelectorCandidate) bool {
	if a.Priority != b.Priority {
		return a.Priority < b.Priority
	}
	return a.NodeID < b.NodeID
}

func betterCandidate(p contract.SelectorPolicy, a contract.SelectorCandidate, am contract.SelectorCandidateStatus, b contract.SelectorCandidate, bm contract.SelectorCandidateStatus) bool {
	if p.ReturnToPreferred && p.PreferredID != "" && p.Mode == "failover" {
		if (a.NodeID == p.PreferredID) != (b.NodeID == p.PreferredID) {
			return a.NodeID == p.PreferredID
		}
	}
	switch p.Mode {
	case "lowest_latency":
		if am.RTTMS != bm.RTTMS {
			return am.RTTMS < bm.RTTMS
		}
	case "highest_throughput":
		if am.DownloadMbps != bm.DownloadMbps {
			return am.DownloadMbps > bm.DownloadMbps
		}
	case "balanced":
		if am.Score != bm.Score {
			return am.Score > bm.Score
		}
	}
	return priorityLess(a, b)
}

func scoreCandidate(p contract.SelectorPolicy, in selectionInput, now time.Time) contract.SelectorCandidateStatus {
	c := contract.SelectorCandidateStatus{Circuit: in.circuit, Evidence: "unknown", NodeID: in.config.NodeID, State: "unknown", ActiveConnections: in.active}
	if !in.enabled || !in.config.Enabled {
		c.State, c.Reason = "disabled", "disabled"
		return c
	}
	trial := in.circuit != nil && in.circuit.State == "half_open"
	var successes, failures int
	var lastAt int64
	for _, s := range in.health.Samples {
		if s.At > now.UnixMilli() || now.UnixMilli()-s.At > p.MaxAgeMS {
			continue
		}
		lastAt = max(lastAt, s.At)
		if !s.OK {
			failures++
		} else {
			if s.Kind != "response" {
				successes++
			}
			if evidenceStrength(s.Kind) > evidenceStrength(c.Evidence) {
				c.Evidence = s.Kind
			}
		}
	}
	latencySamples := in.health.LatencySamples
	if latencySamples == nil {
		latencySamples = in.health.Samples
	}
	for _, s := range latencySamples {
		if s.At > now.UnixMilli() || now.UnixMilli()-s.At > p.MaxAgeMS {
			continue
		}
		target, kind := p.LatencyTarget, "https"
		if in.udp {
			target, kind = p.UDPLatencyTarget, "dns"
		}
		if s.OK && s.Kind == kind && s.Target == target && s.RTTMS > 0 && !math.IsNaN(s.RTTMS) && !math.IsInf(s.RTTMS, 0) {
			if c.Samples == 0 {
				c.RTTMS = s.RTTMS
			} else {
				c.JitterMS = .8*c.JitterMS + .2*math.Abs(s.RTTMS-c.RTTMS)
				c.RTTMS = .8*c.RTTMS + .2*s.RTTMS
			}
			c.Samples++
		}
	}
	if successes+failures > 0 {
		c.FailureRate = float64(failures) / float64(successes+failures)
	}
	speed := in.speed
	speedValid := speed.OK && speed.Samples >= p.MinSamples && speed.At <= now.UnixMilli() && now.UnixMilli()-speed.At <= p.MaxAgeMS &&
		speed.Target == p.SpeedTarget && speed.Target != "" && speed.DownloadMbps > 0 && !math.IsInf(speed.DownloadMbps, 0) && !math.IsNaN(speed.DownloadMbps)
	if speedValid {
		c.DownloadMbps, c.UploadMbps = speed.DownloadMbps, speed.UploadMbps
	}
	if in.circuit != nil && in.circuit.State == "open" {
		c.State, c.Reason = "unhealthy", "circuit_open"
		return c
	}
	if lastAt == 0 && !trial {
		c.Reason = "no_recent_remote_evidence"
		return c
	}
	if in.circuit == nil && (in.health.ConsecutiveFailures >= p.FailureThreshold || (successes+failures >= p.MinSamples && c.FailureRate >= p.MaxFailureRate)) {
		c.State, c.Reason = "unhealthy", "failure_threshold"
		return c
	}
	if in.circuit == nil && failures > 0 && in.health.ConsecutiveFailures == 0 && in.health.ConsecutiveSuccesses < p.RecoveryThreshold {
		c.State, c.Reason = "degraded", "recovering"
		return c
	}
	if successes == 0 && !trial {
		c.State, c.Reason = "degraded", "no_successful_remote_evidence"
		return c
	}
	c.State = "healthy"
	if in.health.ConsecutiveFailures > 0 {
		c.State = "degraded"
	}
	if p.Mode == "lowest_latency" || (p.Mode == "balanced" && (p.Weights.RTT > 0 || p.Weights.Jitter > 0)) {
		if c.Samples < p.MinSamples {
			c.Reason = "insufficient_comparable_rtt"
			return c
		}
	}
	if c.RTTMS > p.MaxRTTMS {
		c.Reason = "rtt_limit"
		return c
	}
	if p.Mode == "highest_throughput" || p.MinDownloadMbps > 0 || p.MinUploadMbps > 0 || (p.Mode == "balanced" && (p.Weights.Download > 0 || p.Weights.Upload > 0)) {
		if !speedValid {
			c.Reason = "no_fresh_speed_measurement"
			return c
		}
	}
	if c.DownloadMbps < p.MinDownloadMbps || c.UploadMbps < p.MinUploadMbps {
		c.Reason = "throughput_limit"
		return c
	}
	if p.Mode == "balanced" && p.Weights.Upload > 0 && c.UploadMbps <= 0 {
		c.Reason = "no_upload_measurement"
		return c
	}
	if p.Mode == "weighted" && in.config.Weight == 0 {
		c.Reason = "zero_weight"
		return c
	}
	c.Eligible, c.Reason = true, "eligible"
	if trial {
		c.State, c.Reason = "degraded", "recovery_trial"
	}
	if p.Mode == "balanced" {
		w := p.Weights
		c.Components = &contract.SelectorScoreComponents{
			RTT:       w.RTTReferenceMS / (w.RTTReferenceMS + c.RTTMS),
			Download:  c.DownloadMbps / (w.DownloadReferenceMbps + c.DownloadMbps),
			Upload:    c.UploadMbps / (w.UploadReferenceMbps + c.UploadMbps),
			Stability: 1 - c.FailureRate,
			Jitter:    w.RTTReferenceMS / (w.RTTReferenceMS + c.JitterMS),
			Load:      w.LoadReference / (w.LoadReference + float64(max(in.active, 0))),
		}
		c.Score = (w.RTT*c.Components.RTT + w.Download*c.Components.Download + w.Upload*c.Components.Upload +
			w.Stability*c.Components.Stability + w.Jitter*c.Components.Jitter + w.Load*c.Components.Load) / (w.RTT + w.Download + w.Upload + w.Stability + w.Jitter + w.Load)
	}
	return c
}

// compileWeights is outside the connection path. pickWeighted uses O(log n)
// comparisons and no allocations for new connections only.
type weightedChoice struct {
	index      int
	cumulative uint64
}

func compileWeights(inputs []selectionInput, candidates []contract.SelectorCandidateStatus) ([]weightedChoice, uint64) {
	var total uint64
	choices := make([]weightedChoice, 0, len(inputs))
	for i, c := range candidates {
		if !c.Eligible {
			continue
		}
		total += uint64(inputs[i].config.Weight)
		choices = append(choices, weightedChoice{i, total})
	}
	return choices, total
}
func pickWeighted(choices []weightedChoice, ticket uint64) int {
	i, _ := slices.BinarySearchFunc(choices, ticket+1, func(c weightedChoice, t uint64) int { return cmp.Compare(c.cumulative, t) })
	return choices[i].index
}

func compileSelectionOrder(selector contract.Selector, inputs []selectionInput, d contract.SelectorDecision) []string {
	if selector.Policy == nil || selector.Policy.Effective().Mode == "manual" || selector.Policy.Locked {
		return []string{d.NodeID}
	}
	indices := make([]int, 0, len(inputs))
	for i, c := range d.Candidates {
		if c.Eligible || (selector.Policy.Fallback == "priority_unknown" && c.State == "unknown" && inputs[i].enabled && inputs[i].config.Enabled && (selector.Policy.Mode != "weighted" || inputs[i].config.Weight > 0)) {
			indices = append(indices, i)
		}
	}
	p := selector.Policy.Effective()
	slices.SortFunc(indices, func(a, b int) int {
		if betterCandidate(p, inputs[a].config, d.Candidates[a], inputs[b].config, d.Candidates[b]) {
			return -1
		}
		if betterCandidate(p, inputs[b].config, d.Candidates[b], inputs[a].config, d.Candidates[a]) {
			return 1
		}
		return 0
	})
	order := make([]string, 0, len(indices)+1)
	if d.NodeID != "" {
		order = append(order, d.NodeID)
	}
	for _, i := range indices {
		if inputs[i].config.NodeID != d.NodeID {
			order = append(order, inputs[i].config.NodeID)
		}
	}
	return order
}

func evidenceStrength(kind string) int {
	switch kind {
	case "native":
		return 4
	case "https", "dns", "doq", "stun", "stun_tcp":
		return 3
	case "response", "reply", "https_get":
		return 2
	case "connect", "tcp_connect":
		return 1
	default:
		return 0
	}
}
