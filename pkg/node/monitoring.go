package node

import (
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/latency"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"golang.org/x/time/rate"
)

var errProbeSkipped = errors.New("probe skipped by network cost or runtime policy")

func monitoringAllowed(platform string, network contract.MonitoringNetworkState, mobile bool, metered bool) bool {
	return network.Online && (!network.Metered || metered) && (platform != "android" || (mobile && network.Foreground))
}
func (s *selectorRuntime) effectivePolicy(config contract.Selector) contract.Selector {
	return policyWithMonitoringDefaults(config, s.defaults)
}
func policyWithMonitoringDefaults(config contract.Selector, defaults contract.MonitoringConfig) contract.Selector {
	if config.Policy == nil {
		return config
	}
	p := *config.Policy
	probe := defaults.Probe
	if p.Probe != nil {
		probe = p.Probe.Effective()
	}
	if p.LatencyTarget == "" {
		p.LatencyTarget = probe.LatencyTarget
	}
	if p.UDPLatencyTarget == "" {
		p.UDPLatencyTarget = probe.DNSAddress + "/" + probe.DNSDomain
	}
	if p.SpeedTarget == "" {
		speed := defaults.Speed
		if p.PeriodicSpeed != nil {
			speed = p.PeriodicSpeed.Effective()
		}
		p.SpeedTarget = speed.Test.URL
		if p.SpeedTest != nil && p.SpeedTest.URL != "" {
			p.SpeedTarget = p.SpeedTest.URL
		}
	}
	if p.UploadTarget == "" {
		speed := contract.SpeedSchedule{}.WithDirection("upload")
		if defaults.UploadSpeed != nil {
			speed = defaults.UploadSpeed.WithDirection("upload")
		}
		if p.PeriodicUpload != nil {
			speed = p.PeriodicUpload.WithDirection("upload")
		}
		p.UploadTarget = speed.Test.URL
		if p.UploadTest != nil && p.UploadTest.URL != "" {
			p.UploadTarget = p.UploadTest.URL
		}
	}
	if p.FailureThreshold == 0 {
		p.FailureThreshold = probe.FailureThreshold
	}
	if p.RecoveryThreshold == 0 {
		p.RecoveryThreshold = probe.RecoveryThreshold
	}
	if p.MaxAgeMS == 0 && probe.Enabled {
		// The lifetime must cover the sample threshold at the actual probe rate.
		p.MaxAgeMS = min(max(120_000, int64(p.Effective().MinSamples)*probePeriodMS(probe)), 86_400_000)
	}
	if (p.Fallback == "" || p.Fallback == "reject") && !probe.Enabled && (p.Mode == "failover" || p.Mode == "weighted") {
		// These modes learn from passive traffic, which rejection would stop for
		// good once evidence expires. Unknown candidates stay admissible; those
		// with recent failures or an open circuit remain rejected.
		p.Fallback = "priority_unknown"
	}
	config.Policy = &p
	return config
}

// probePeriodMS is the longest regular time between two samples of one job: the
// next run is scheduled after completion, including a budget wait and a timeout.
func probePeriodMS(probe contract.ProbeSchedule) int64 {
	return int64(float64(probe.IntervalMS)*(1+probe.Jitter)) + 2*probe.TimeoutMS
}

func selectorSchedules(p contract.SelectorPolicy, defaults contract.MonitoringConfig) (contract.ProbeSchedule, contract.SpeedSchedule, contract.SpeedSchedule) {
	probe := defaults.Probe
	if p.Probe != nil {
		probe = p.Probe.Effective()
	}
	speed := defaults.Speed
	if p.PeriodicSpeed != nil {
		speed = p.PeriodicSpeed.Effective()
	}
	upload := contract.SpeedSchedule{}.WithDirection("upload")
	if defaults.UploadSpeed != nil {
		upload = defaults.UploadSpeed.WithDirection("upload")
	}
	if p.PeriodicUpload != nil {
		upload = p.PeriodicUpload.WithDirection("upload")
	}
	return probe, speed, upload
}

// validateSelectorEvidence refuses a policy that contradicts itself. Manual
// measurements remain a supported source, so an absent schedule is only a warning.
func validateSelectorEvidence(config contract.Selector, defaults contract.MonitoringConfig) error {
	if config.Policy == nil {
		return nil
	}
	config = policyWithMonitoringDefaults(config, defaults)
	p := config.Policy.Effective()
	if p.Mode == "manual" || p.Locked {
		return nil
	}
	probe, _, _ := selectorSchedules(p, defaults)
	if selectorNeedsRTT(p) && probe.Enabled {
		if required := int64(p.MinSamples-1) * probePeriodMS(probe); p.MaxAgeMS < required {
			return fmt.Errorf("selector %q: maxAgeMs must be at least %d to retain %d samples at the probe interval", config.Name, required, p.MinSamples)
		}
	}
	if p.Fallback == "selected" && !slices.ContainsFunc(p.Candidates, func(c contract.SelectorCandidate) bool { return c.NodeID == config.NodeID && c.Enabled }) {
		return fmt.Errorf("selector %q: fallback to the selected node requires it to be an enabled candidate", config.Name)
	}
	return nil
}

func selectorNeedsRTT(p contract.SelectorPolicy) bool {
	return p.Mode == "lowest_latency" || (p.Mode == "balanced" && (p.Weights.RTT > 0 || p.Weights.Jitter > 0))
}

// selectorEvidenceGap names a measurement only a person can currently provide:
// without it every new flow is rejected once earlier results expire.
func selectorEvidenceGap(config contract.Selector, defaults contract.MonitoringConfig) string {
	if config.Policy == nil {
		return ""
	}
	config = policyWithMonitoringDefaults(config, defaults)
	p := config.Policy.Effective()
	if p.Mode == "manual" || p.Locked || p.Fallback == "selected" {
		return ""
	}
	probe, speed, upload := selectorSchedules(p, defaults)
	switch {
	case selectorNeedsRTT(p) && (!probe.Enabled || !slices.ContainsFunc(probe.Kinds, func(kind string) bool { return kind == "https" || kind == "dns" || kind == "udp" })):
		return "enabled https or dns probes"
	case (p.Mode == "highest_throughput" || p.MinDownloadMbps > 0 || (p.Mode == "balanced" && p.Weights.Download > 0)) && (!speed.Enabled || p.SpeedTarget == ""):
		return "an enabled periodic speed test"
	case (p.MinUploadMbps > 0 || (p.Mode == "balanced" && p.Weights.Upload > 0)) && (!upload.Enabled || p.UploadTarget == ""):
		return "an enabled periodic upload test"
	}
	return ""
}
func (s *selectorRuntime) scheduleLocked() {
	var jobs []probeJob
	rates := map[int64]bool{}
	for _, config := range s.configs {
		if config.Policy == nil {
			continue
		}
		config = s.effectivePolicy(config)
		p := config.Policy.Effective()
		if p.Mode == "manual" || p.Locked {
			continue
		}
		probe, speed, upload := selectorSchedules(p, s.defaults)
		for _, candidate := range p.Candidates {
			n, ok := s.nodes[candidate.NodeID]
			if !ok || !n.Enabled || !candidate.Enabled {
				continue
			}
			encoded, _ := json.Marshal(n)
			nodeSignature := fmt.Sprintf("%x", sha256.Sum256(encoded))
			if probe.Enabled && monitoringAllowed(s.platform, s.network, probe.AllowMobile, probe.NetworkCostPolicy == "allow_expensive") {
				rates[probe.MaxProbeBandwidth] = true
				for _, kind := range probe.Kinds {
					req := contract.LatencyRequest{Type: kind, Host: probe.TCPAddress}
					switch kind {
					case "https":
						req.Type, req.URL = "https", p.LatencyTarget
					case "dns", "udp":
						req.Type = "dns"
						req.Host, req.TargetDomain, _ = strings.Cut(p.UDPLatencyTarget, "/")
					case "stun":
						req.Host = probe.STUNAddress
					case "native":
						req = contract.LatencyRequest{Type: "native"}
					}
					// Only equivalent execution policies can share a job. The interval
					// is excluded so identical probes run at the shortest requested rate.
					payload, _ := json.Marshal(struct {
						Request           contract.LatencyRequest
						TimeoutMS         int64
						CooldownMS        int64
						MaxProbeBandwidth int64
						Concurrency       int
						FailureThreshold  int
						Jitter            float64
						NetworkCostPolicy string
					}{
						Request:           req,
						TimeoutMS:         probe.TimeoutMS,
						CooldownMS:        probe.CooldownMS,
						MaxProbeBandwidth: probe.MaxProbeBandwidth,
						Concurrency:       probe.Concurrency,
						FailureThreshold:  probe.FailureThreshold,
						Jitter:            probe.Jitter,
						NetworkCostPolicy: probe.NetworkCostPolicy,
					})
					digest := sha256.Sum256(payload)
					key := n.ID + "/" + fmt.Sprintf("%x", digest)
					jobs = append(jobs, probeJob{group: fmt.Sprintf("probe:%d", probe.Concurrency), key: key, cooldown: time.Duration(probe.CooldownMS) * time.Millisecond, failureThreshold: probe.FailureThreshold, signature: nodeSignature + fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprint(probe)))), interval: time.Duration(probe.IntervalMS) * time.Millisecond, timeout: 2 * time.Duration(probe.TimeoutMS) * time.Millisecond, jitter: probe.Jitter, concurrency: probe.Concurrency, run: func(ctx context.Context) error { return s.runProbe(ctx, n, probe, req) }})
				}
			}
			for _, direction := range []struct {
				schedule     contract.SpeedSchedule
				override     *contract.SpeedTestRequest
				target, name string
			}{{speed, p.SpeedTest, p.SpeedTarget, "download"}, {upload, p.UploadTest, p.UploadTarget, "upload"}} {
				schedule := direction.schedule.WithDirection(direction.name)
				if !schedule.Enabled || !monitoringAllowed(s.platform, s.network, schedule.AllowMobile, schedule.AllowMetered) {
					continue
				}
				request := schedule.Test
				if direction.override != nil {
					request = *direction.override
				}
				if request.Direction == "" {
					request.Direction = direction.name
				}
				if direction.target != "" {
					request.URL = direction.target
				}
				request = request.Effective()
				if request.Direction != direction.name || request.Validate() != nil {
					continue
				}
				// As with health probes, only equivalent execution settings can
				// share a speed test; interval is resolved to the shortest rate.
				raw, _ := json.Marshal(struct {
					Request           contract.SpeedTestRequest
					Concurrency       int
					Jitter            float64
					NetworkCostPolicy string
				}{
					Request:           request,
					Concurrency:       schedule.Concurrency,
					Jitter:            probe.Jitter,
					NetworkCostPolicy: probe.NetworkCostPolicy,
				})
				digest := sha256.Sum256(raw)
				key := n.ID + "/speed/" + fmt.Sprintf("%x", digest)
				jobs = append(jobs, probeJob{group: "speed", key: key, signature: nodeSignature + probe.NetworkCostPolicy, interval: time.Duration(schedule.IntervalMS) * time.Millisecond, timeout: time.Duration(request.TimeoutMS) * time.Millisecond, jitter: probe.Jitter, concurrency: schedule.Concurrency, run: func(ctx context.Context) error {
					if !s.probeCanStart(n, probe.NetworkCostPolicy) {
						return errProbeSkipped
					}
					_, err := s.runtime.Speed(netapi.WithBackgroundProbe(ctx), n.ID, request)
					if errors.Is(err, errSpeedBusy) || errors.Is(err, errSpeedBudget) || errors.Is(err, errMeasurementBusy) || localProbeDenial(err) {
						return errProbeSkipped
					}
					return err
				}})
			}
		}
	}
	if s.probeRateOverrides == nil {
		s.probeRateOverrides = map[int64]*rate.Limiter{}
	}
	for bytes := range rates {
		if bytes < s.defaults.Probe.MaxProbeBandwidth && s.probeRateOverrides[bytes] == nil {
			s.probeRateOverrides[bytes] = newProbeLimiter(bytes)
		}
	}
	for bytes := range s.probeRateOverrides {
		if !rates[bytes] {
			delete(s.probeRateOverrides, bytes)
		}
	}
	s.scheduler.replace(jobs, s.defaults.Probe.Concurrency)
}
func (s *selectorRuntime) probeCanStart(n contract.Node, policy string) bool {
	entry, cached := s.runtime.proxies.store.Load(n.ID)
	if cached {
		if entry.mu.TryRLock() {
			if provider, ok := entry.Proxy.(contract.NodeRuntimeStatusProvider); ok {
				state := provider.NodeRuntimeStatus().State
				cached = state == "connected" || state == "configured"
			}
			entry.mu.RUnlock()
		} else {
			cached = false
		}
	}
	if cached {
		return true
	}
	if policy == "cached_only" {
		return false
	}
	// Enterprise VPN constructors may initiate costly external authentication.
	// Periodic work never starts these; an administrator establishes them once
	// through the existing manual path, after which periodic probes may reuse it.
	return !requiresEstablishedClient(n.Chain)
}

func requiresEstablishedClient(chain []contract.Protocol) bool {
	for _, p := range chain {
		if slices.Contains([]string{"openvpn", "ikev2", "anyconnect", "sstp", "fortinet", "globalprotect", "softether", "l2tp", "l2tpv3", "tailscale", "nebula", "zerotier", "set", "point_as_endpoint"}, p.Type) {
			return true
		}
		if p.NetworkSplit != nil {
			for _, child := range []*contract.Protocol{p.NetworkSplit.TCP, p.NetworkSplit.UDP} {
				if child != nil && requiresEstablishedClient([]contract.Protocol{*child}) {
					return true
				}
			}
		}
	}
	return false
}

func (s *selectorRuntime) runProbe(ctx context.Context, n contract.Node, options contract.ProbeSchedule, req contract.LatencyRequest) (resultErr error) {
	ctx = netapi.WithBackgroundProbe(ctx)
	var duration time.Duration
	ok := true
	defer func() {
		s.runtime.metrics.observeProbe(req.Type, ok, resultErr, duration)
	}()
	if req.Type == "native" {
		return s.nativeProbe(ctx, n.ID)
	}
	if !s.probeCanStart(n, options.NetworkCostPolicy) {
		return errProbeSkipped
	}
	// Reserve the complete per-probe byte allowance before starting the timing
	// window. Waiting for the resource budget must not inflate measured RTT or
	// count as remote failure, so the wait and the probe have separate timeouts
	// within the job's limit, and the wait holds no measurement slot. One shared
	// limiter bounds all selectors together.
	timeout := time.Duration(options.Effective().TimeoutMS) * time.Millisecond
	waitCtx, cancelWait := context.WithTimeout(ctx, timeout)
	err := s.waitProbeBudget(waitCtx, options.MaxProbeBandwidth)
	cancelWait()
	if err != nil {
		return errProbeSkipped
	}
	lease, err := s.runtime.admitMeasurement(ctx, n.ID)
	if err != nil {
		return errProbeSkipped
	}
	defer lease.release()
	ctx, cancel := context.WithTimeout(lease.ctx, timeout)
	defer cancel()
	current, epoch, err := s.runtime.cachedNode(ctx, n.ID)
	if err != nil {
		return err
	}
	proxy, err := s.runtime.probeDialer(ctx, n.ID, current, epoch, true)
	if err != nil {
		if ctx.Err() == nil && !errors.Is(err, errProbePolicyUnavailable) {
			s.runtime.observer.counter(n.ID).constructionFailureAtGeneration(err, epoch)
		}
		if errors.Is(err, errProbePolicyUnavailable) {
			return errProbeSkipped
		}
		return err
	}
	budget := newProbeBudgetProxy(proxy)
	start := time.Now()
	result, err := latency.LatencyWithContext(ctx, req, budget, latency.LatencyOptions{})
	ok = result.OK
	duration = time.Since(start)
	err = classifyProbeError(proxy, err)
	if errors.Is(ctx.Err(), context.Canceled) {
		return ctx.Err()
	}
	if errors.Is(err, errProbeByteBudget) || localProbeDenial(err) {
		return errProbeSkipped
	}
	kind, target, tcp := req.Type, req.Host, true
	switch req.Type {
	case "https":
		target = req.URL
	case "dns":
		target = req.Host + "/" + req.TargetDomain
		tcp = false
	case "stun":
		tcp = false
	}
	c := s.runtime.observer.counter(n.ID)
	c.probeAtGeneration(kind, result, err, epoch)
	sample := contract.HealthSample{At: time.Now().UnixMilli(), OK: result.OK, Kind: kind, Target: target, RTTMS: float64(duration) / float64(time.Millisecond)}
	if err == nil || healthFailure(err) {
		c.remoteEvidenceAtGeneration(tcp, sample, err, epoch)
	} else if !neutralProbeError(err) {
		// A completed end-to-end probe that ends in EOF or a protocol error shows
		// this path cannot deliver, even when passive traffic would stay neutral.
		c.remoteEvidenceAtGeneration(tcp, sample, nil, epoch)
	}
	s.mu.Lock()
	s.rebuild(time.Now())
	s.mu.Unlock()
	return err
}

// These outcomes say nothing about the candidate's ability to carry traffic.
func neutralProbeError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, errNodeReconfigured) || errors.Is(err, errors.ErrUnsupported) || errors.Is(err, latency.ErrProbeRedirect)
}
func (s *selectorRuntime) nativeProbe(ctx context.Context, id string) error {
	epoch := s.runtime.observer.counter(id).generation.Load()
	var native *contract.ProtocolRuntimeStatus
	if entry, ok := s.runtime.proxies.store.Load(id); ok && entry.mu.TryRLock() {
		if provider, ok := entry.Proxy.(contract.NodeRuntimeStatusProvider); ok {
			v := provider.NodeRuntimeStatus()
			native = &v
		}
		entry.mu.RUnlock()
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if native == nil || native.UpdatedAt <= 0 || time.Now().Unix()-native.UpdatedAt > 120 || native.UpdatedAt > time.Now().Unix()+5 {
		return errProbeSkipped
	}
	if !slices.Contains([]string{"connected", "healthy", "ready", "disconnected", "failed", "unhealthy"}, native.State) {
		return errProbeSkipped
	}
	ok := slices.Contains([]string{"connected", "healthy", "ready"}, native.State)
	// Native evidence supplements both transports only when the protocol itself
	// claims a completed tunnel state. PacketConn construction does not do this.
	c := s.runtime.observer.counter(id)
	for _, tcp := range []bool{true, false} {
		c.remoteEvidenceAtGeneration(tcp, contract.HealthSample{At: time.Now().UnixMilli(), OK: ok, Kind: "native"}, nil, epoch)
	}
	if !ok {
		return errors.New("native tunnel reports unavailable")
	}
	return nil
}
func (s *selectorRuntime) monitoringStatus() contract.MonitoringStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.scheduler.status()
	config := s.defaults
	config.Probe.Kinds = slices.Clone(config.Probe.Kinds)
	return contract.MonitoringStatus{ActiveMeasurements: int(s.runtime.measurementActive.Load()), MeasurementLimit: int(s.runtime.measurementLimit.Load()), PolicyState: s.runtime.probePolicyState(), Config: config, Network: s.network, Platform: s.platform, Jobs: v.Jobs, Running: v.Running, Workers: v.Workers, Completed: v.Completed, Failed: v.Failed, Skipped: v.Skipped}
}
func (r *NodeRuntime) Monitoring(ctx context.Context) (contract.MonitoringStatus, error) {
	if _, err := r.openNodes(ctx); err != nil {
		return contract.MonitoringStatus{}, err
	}
	return r.selectors.monitoringStatus(), nil
}
func (r *NodeRuntime) SaveMonitoring(ctx context.Context, c contract.MonitoringConfig) (contract.MonitoringStatus, error) {
	nodes, err := r.openNodes(ctx)
	if err != nil {
		return contract.MonitoringStatus{}, err
	}
	if err := c.Validate(); err != nil {
		return contract.MonitoringStatus{}, err
	}
	// Validate speed budgets at configuration time as well as at execution time.
	if c.Speed.Enabled {
		if _, err := latency.ValidateSpeedTest(c.Speed.Test); err != nil {
			return contract.MonitoringStatus{}, err
		}
	}
	r.selectors.mu.Lock()
	for _, selector := range r.selectors.configs {
		effective := policyWithMonitoringDefaults(selector, c.Effective())
		if effective.Policy != nil {
			if err := effective.Policy.Validate(); err != nil {
				r.selectors.mu.Unlock()
				return contract.MonitoringStatus{}, err
			}
		}
		if err := validateSelectorEvidence(selector, c.Effective()); err != nil {
			r.selectors.mu.Unlock()
			return contract.MonitoringStatus{}, err
		}
		if gap := selectorEvidenceGap(selector, c.Effective()); gap != "" {
			log.Warn("selector will reject new flows without manual measurements", "selector", selector.Name, "requires", gap)
		}
	}
	r.selectors.mu.Unlock()
	if err := r.selectors.monitorStore.Save(ctx, c); err != nil {
		return contract.MonitoringStatus{}, err
	}
	if err := r.refreshSelectors(ctx, nodes); err != nil {
		return contract.MonitoringStatus{}, err
	}
	return r.selectors.monitoringStatus(), nil
}
func (r *NodeRuntime) SetMonitoringNetworkState(ctx context.Context, n contract.MonitoringNetworkState) (contract.MonitoringStatus, error) {
	if _, err := r.openNodes(ctx); err != nil {
		return contract.MonitoringStatus{}, err
	}
	s := r.selectors
	s.mu.Lock()
	if n.Generation <= s.network.Generation {
		n.Generation = s.network.Generation + 1
	}
	s.network = n
	// Cancel all old-interface jobs first, even if the targets did not change.
	s.scheduler.replace(nil, s.defaults.Probe.Concurrency)
	s.scheduleLocked()
	s.mu.Unlock()
	return s.monitoringStatus(), nil
}

func defaultMonitoringNetwork() contract.MonitoringNetworkState {
	return contract.MonitoringNetworkState{Online: true, Foreground: runtime.GOOS != "android"}
}
func newProbeLimiter(bytesPerSecond int64) *rate.Limiter {
	return rate.NewLimiter(rate.Limit(bytesPerSecond), int(probeByteBudget))
}
