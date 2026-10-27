package node

import (
	"errors"
	"fmt"
	"math"
	"strings"
)

// SelectorPolicy is opt-in. A nil policy and an empty mode retain the legacy
// fixed NodeID choice. Durations in this API are milliseconds.
type SelectorPolicy struct {
	Circuit        *CircuitConfig      `json:"circuit,omitzero"`
	Probe          *ProbeSchedule      `json:"probe,omitzero"`
	PeriodicUpload *SpeedSchedule      `json:"periodicUpload,omitzero"`
	PeriodicSpeed  *SpeedSchedule      `json:"periodicSpeed,omitzero"`
	Mode           string              `json:"mode,omitempty"`
	Candidates     []SelectorCandidate `json:"candidates,omitempty"`
	PreferredID    string              `json:"preferredId,omitempty"`
	Locked         bool                `json:"locked,omitzero"`
	// Fallback is reject (default), selected, or priority_unknown. It never
	// bypasses routing by falling back to Direct.
	Fallback              string            `json:"fallback,omitempty"`
	ReturnToPreferred     bool              `json:"returnToPreferred,omitzero"`
	LatencyTarget         string            `json:"latencyTarget,omitempty"`
	UDPLatencyTarget      string            `json:"udpLatencyTarget,omitempty"`
	UploadTarget          string            `json:"uploadTarget,omitempty"`
	UploadTest            *SpeedTestRequest `json:"uploadTest,omitzero"`
	SpeedTarget           string            `json:"speedTarget,omitempty"`
	SpeedTest             *SpeedTestRequest `json:"speedTest,omitzero"`
	MinSamples            int               `json:"minSamples,omitzero"`
	FailureThreshold      int               `json:"failureThreshold,omitzero"`
	RecoveryThreshold     int               `json:"recoveryThreshold,omitzero"`
	MaxAgeMS              int64             `json:"maxAgeMs,omitzero"`
	MaxRTTMS              float64           `json:"maxRttMs,omitzero"`
	MaxFailureRate        float64           `json:"maxFailureRate,omitzero"`
	MinImprovementMS      float64           `json:"minImprovementMs,omitzero"`
	MinImprovementPercent float64           `json:"minImprovementPercent,omitzero"`
	MinScoreImprovement   float64           `json:"minScoreImprovement,omitzero"`
	MinHoldMS             int64             `json:"minHoldMs,omitzero"`
	CooldownMS            int64             `json:"cooldownMs,omitzero"`
	MinDownloadMbps       float64           `json:"minDownloadMbps,omitzero"`
	MinUploadMbps         float64           `json:"minUploadMbps,omitzero"`
	Weights               SelectorWeights   `json:"weights"`
}

type SelectorCandidate struct {
	NodeID   string `json:"nodeId"`
	Enabled  bool   `json:"enabled"`
	Priority int    `json:"priority"`
	Weight   uint32 `json:"weight"`
}

// Weights multiply bounded [0,1] components. Reference values are saturation
// points, not promises about path capacity. Passive business Bps is never used
// as a capacity measurement.
type SelectorWeights struct {
	RTT                   float64 `json:"rtt,omitzero"`
	Download              float64 `json:"download,omitzero"`
	Upload                float64 `json:"upload,omitzero"`
	Stability             float64 `json:"stability,omitzero"`
	Jitter                float64 `json:"jitter,omitzero"`
	Load                  float64 `json:"load,omitzero"`
	RTTReferenceMS        float64 `json:"rttReferenceMs,omitzero"`
	DownloadReferenceMbps float64 `json:"downloadReferenceMbps,omitzero"`
	UploadReferenceMbps   float64 `json:"uploadReferenceMbps,omitzero"`
	LoadReference         float64 `json:"loadReference,omitzero"`
}

func (p SelectorPolicy) Effective() SelectorPolicy {
	if p.Mode == "" {
		p.Mode = "manual"
	}
	if p.Fallback == "" {
		p.Fallback = "reject"
	}
	if p.UDPLatencyTarget == "" {
		p.UDPLatencyTarget = "223.5.5.5:53/www.google.com"
	}
	if p.LatencyTarget == "" {
		p.LatencyTarget = "https://www.gstatic.com/generate_204"
	}
	if p.MinSamples == 0 {
		p.MinSamples = 3
	}
	if p.FailureThreshold == 0 {
		p.FailureThreshold = 3
	}
	if p.RecoveryThreshold == 0 {
		p.RecoveryThreshold = 2
	}
	if p.MaxAgeMS == 0 {
		p.MaxAgeMS = 120_000
	}
	if p.MaxRTTMS == 0 {
		p.MaxRTTMS = 5000
	}
	if p.MaxFailureRate == 0 {
		p.MaxFailureRate = .5
	}
	if p.MinImprovementMS == 0 {
		p.MinImprovementMS = 10
	}
	if p.MinImprovementPercent == 0 {
		p.MinImprovementPercent = 10
	}
	if p.MinScoreImprovement == 0 {
		p.MinScoreImprovement = .05
	}
	if p.MinHoldMS == 0 {
		p.MinHoldMS = 30_000
	}
	if p.CooldownMS == 0 {
		p.CooldownMS = 15_000
	}
	w := &p.Weights
	if w.RTT+w.Download+w.Upload+w.Stability+w.Jitter+w.Load == 0 {
		w.RTT, w.Download, w.Stability = .5, .3, .2
	}
	if w.RTTReferenceMS == 0 {
		w.RTTReferenceMS = 100
	}
	if w.DownloadReferenceMbps == 0 {
		w.DownloadReferenceMbps = 100
	}
	if w.UploadReferenceMbps == 0 {
		w.UploadReferenceMbps = 30
	}
	if w.LoadReference == 0 {
		w.LoadReference = 100
	}
	return p
}

func (p SelectorPolicy) Validate() error {
	p = p.Effective()
	if p.Circuit != nil {
		if err := p.Circuit.Validate(p.RecoveryThreshold); err != nil {
			return err
		}
	}
	if err := validateHTTPSProbeURL(p.LatencyTarget); err != nil {
		return err
	}
	for _, target := range []string{p.SpeedTarget, p.UploadTarget} {
		if target != "" {
			if err := validateHTTPSProbeURL(target); err != nil {
				return err
			}
		}
	}
	for _, entry := range []struct {
		request           *SpeedTestRequest
		target, direction string
	}{
		{p.SpeedTest, p.SpeedTarget, "download"}, {p.UploadTest, p.UploadTarget, "upload"},
	} {
		if entry.request == nil {
			continue
		}
		request := *entry.request
		if request.Direction == "" {
			request.Direction = entry.direction
		}
		if request.Direction != entry.direction {
			return errors.New("speed test direction does not match its configured slot")
		}
		if entry.target != "" {
			request.URL = entry.target
		}
		if request.URL != "" {
			if err := request.Validate(); err != nil {
				return err
			}
		}
	}
	address, domain, ok := strings.Cut(p.UDPLatencyTarget, "/")
	if !ok || validateProbeAddress(address) != nil || !validProbeDomain(domain) {
		return errors.New("UDP latency target requires host:port/domain")
	}
	if p.Probe != nil {
		if err := p.Probe.Validate(); err != nil {
			return err
		}
	}
	for _, entry := range []struct {
		schedule          *SpeedSchedule
		request           *SpeedTestRequest
		target, direction string
	}{
		{p.PeriodicSpeed, p.SpeedTest, p.SpeedTarget, "download"}, {p.PeriodicUpload, p.UploadTest, p.UploadTarget, "upload"},
	} {
		if entry.schedule == nil {
			continue
		}
		speed := entry.schedule.WithDirection(entry.direction)
		if entry.request != nil {
			speed.Test = *entry.request
			speed = speed.WithDirection(entry.direction)
		}
		if speed.Test.Direction != entry.direction {
			return errors.New("speed schedule direction does not match its configured slot")
		}
		if entry.target != "" {
			speed.Test.URL = entry.target
		}
		if err := speed.Validate(); err != nil {
			return err
		}
	}

	switch p.Mode {
	case "manual", "failover", "lowest_latency", "highest_throughput", "balanced", "weighted":
	default:
		return fmt.Errorf("unsupported selector mode %q", p.Mode)
	}
	switch p.Fallback {
	case "reject", "selected", "priority_unknown":
	default:
		return errors.New("unsupported selector fallback")
	}
	if len(p.Candidates) > 1000 || (p.Mode != "manual" && len(p.Candidates) == 0) {
		return errors.New("automatic selector requires 1 to 1000 candidates")
	}
	seen := make(map[string]bool, len(p.Candidates))
	for _, c := range p.Candidates {
		if c.NodeID == "" || seen[c.NodeID] || c.Weight > 1_000_000 {
			return errors.New("invalid or duplicate selector candidate, or excessive weight")
		}
		seen[c.NodeID] = true
	}
	if p.PreferredID != "" && !seen[p.PreferredID] {
		return errors.New("preferred node must be a candidate")
	}
	if p.MinSamples < 1 || p.MinSamples > 64 || p.FailureThreshold < 1 || p.FailureThreshold > 64 ||
		p.RecoveryThreshold < 1 || p.RecoveryThreshold > 64 || p.MaxAgeMS < 1000 || p.MaxAgeMS > 86_400_000 ||
		p.MinHoldMS < 0 || p.MinHoldMS > 86_400_000 || p.CooldownMS < 0 || p.CooldownMS > 86_400_000 {
		return errors.New("selector sample or timing limit is invalid")
	}
	for _, v := range []float64{p.MaxRTTMS, p.MaxFailureRate, p.MinImprovementMS, p.MinImprovementPercent,
		p.MinScoreImprovement, p.MinDownloadMbps, p.MinUploadMbps, p.Weights.RTT, p.Weights.Download,
		p.Weights.Upload, p.Weights.Stability, p.Weights.Jitter, p.Weights.Load, p.Weights.RTTReferenceMS,
		p.Weights.DownloadReferenceMbps, p.Weights.UploadReferenceMbps, p.Weights.LoadReference} {
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v > 1e9 {
			return errors.New("selector values must be finite and nonnegative")
		}
	}
	if p.MaxFailureRate > 1 || p.MinImprovementPercent > 100 || p.MinScoreImprovement > 1 {
		return errors.New("selector ratio is out of range")
	}
	return nil
}
