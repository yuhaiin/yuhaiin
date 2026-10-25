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
	"github.com/Asutorufa/yuhaiin/pkg/net/latency"
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
	}
	if p.FailureThreshold == 0 {
		p.FailureThreshold = probe.FailureThreshold
	}
	if p.RecoveryThreshold == 0 {
		p.RecoveryThreshold = probe.RecoveryThreshold
	}
	config.Policy = &p
	return config
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
		probe := s.defaults.Probe
		if p.Probe != nil {
			probe = p.Probe.Effective()
		}
		speed := s.defaults.Speed
		if p.PeriodicSpeed != nil {
			speed = p.PeriodicSpeed.Effective()
		}
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
					payload, _ := json.Marshal(req)
					digest := sha256.Sum256(payload)
					key := n.ID + "/" + fmt.Sprintf("%x", digest)
					jobs = append(jobs, probeJob{group: fmt.Sprintf("probe:%d", probe.Concurrency), key: key, cooldown: time.Duration(probe.CooldownMS) * time.Millisecond, failureThreshold: probe.FailureThreshold, signature: nodeSignature + fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprint(probe)))), interval: time.Duration(probe.IntervalMS) * time.Millisecond, timeout: time.Duration(probe.TimeoutMS) * time.Millisecond, jitter: probe.Jitter, concurrency: probe.Concurrency, run: func(ctx context.Context) error { return s.runProbe(ctx, n, probe, req) }})
				}
			}
			if speed.Enabled && monitoringAllowed(s.platform, s.network, speed.AllowMobile, speed.AllowMetered) {
				request := speed.Test
				if p.SpeedTest != nil {
					request = *p.SpeedTest
				}
				if p.SpeedTarget != "" {
					request.URL = p.SpeedTarget
				}
				if request.URL == "" {
					continue
				}
				raw, _ := json.Marshal(request)
				digest := sha256.Sum256(raw)
				key := n.ID + "/speed/" + fmt.Sprintf("%x", digest)
				jobs = append(jobs, probeJob{group: "speed", key: key, signature: nodeSignature + probe.NetworkCostPolicy, interval: time.Duration(speed.IntervalMS) * time.Millisecond, timeout: 30 * time.Second, jitter: probe.Jitter, concurrency: speed.Concurrency, run: func(ctx context.Context) error {
					if !s.probeCanStart(n, probe.NetworkCostPolicy) {
						return errProbeSkipped
					}
					_, err := s.runtime.Speed(ctx, n.ID, request)
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
	cached := false
	s.runtime.proxies.Range(func(id string, _ *ProxyEntry) bool {
		if id == n.ID {
			cached = true
			return false
		}
		return true
	})
	if cached {
		return true
	}
	if policy == "cached_only" {
		return false
	}
	// Enterprise VPN constructors may initiate costly external authentication.
	// Periodic work never starts these; an administrator establishes them once
	// through the existing manual path, after which periodic probes may reuse it.
	var expensive func([]contract.Protocol) bool
	expensive = func(chain []contract.Protocol) bool {
		for _, p := range chain {
			if slices.Contains([]string{"openvpn", "ikev2", "anyconnect", "sstp", "fortinet", "globalprotect", "softether", "l2tp", "l2tpv3", "tailscale", "nebula", "zerotier", "set", "point_as_endpoint"}, p.Type) {
				return true
			}
			if p.NetworkSplit != nil {
				for _, child := range []*contract.Protocol{p.NetworkSplit.TCP, p.NetworkSplit.UDP} {
					if child != nil && expensive([]contract.Protocol{*child}) {
						return true
					}
				}
			}
		}
		return false
	}
	return !expensive(n.Chain)
}
func (s *selectorRuntime) runProbe(ctx context.Context, n contract.Node, options contract.ProbeSchedule, req contract.LatencyRequest) (resultErr error) {
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
	// count as remote failure. One shared limiter bounds all selectors together.
	lease, err := s.runtime.admitMeasurement(ctx, n.ID)
	if err != nil {
		return errProbeSkipped
	}
	defer lease.release()
	ctx = lease.ctx
	if err := s.waitProbeBudget(ctx, options.MaxProbeBandwidth); err != nil {
		return errProbeSkipped
	}
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
	c.remoteEvidenceAtGeneration(tcp, contract.HealthSample{At: time.Now().UnixMilli(), OK: result.OK, Kind: kind, Target: target, RTTMS: float64(duration) / float64(time.Millisecond)}, err, epoch)
	s.mu.Lock()
	s.rebuild(time.Now())
	s.mu.Unlock()
	return err
}
func (s *selectorRuntime) nativeProbe(ctx context.Context, id string) error {
	epoch := s.runtime.observer.counter(id).generation.Load()
	var native *contract.ProtocolRuntimeStatus
	s.runtime.proxies.Range(func(key string, p *ProxyEntry) bool {
		if key != id {
			return true
		}
		p.mu.RLock()
		defer p.mu.RUnlock()
		if provider, ok := p.Proxy.(contract.NodeRuntimeStatusProvider); ok {
			v := provider.NodeRuntimeStatus()
			native = &v
		}
		return false
	})
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if native == nil || native.UpdatedAt <= 0 || time.Now().Unix()-native.UpdatedAt > 120 {
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
