package node

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/latency"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/time/rate"
)

type loopbackPacketProxy struct{ netapi.Proxy }

func (loopbackPacketProxy) PacketConn(context.Context, netapi.Address) (net.PacketConn, error) {
	return net.ListenPacket("udp", "127.0.0.1:0")
}

func TestDNSProbeCompletesWithinByteBudget(t *testing.T) {
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := server.ReadFrom(buf)
			if err != nil {
				return
			}
			var m dnsmessage.Message
			if m.Unpack(buf[:n]) != nil {
				continue
			}
			m.Response = true
			if len(m.Questions) > 0 && m.Questions[0].Type == dnsmessage.TypeA {
				m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: m.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{1, 2, 3, 4}}}}
			}
			out, _ := m.Pack()
			_, _ = server.WriteTo(out, addr)
		}
	}()
	for range 8 {
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		_, err := latency.DNSWithContext(ctx, newProbeBudgetProxy(loopbackPacketProxy{netapi.NewErrProxy(net.ErrClosed)}), server.LocalAddr().String(), "www.example.com")
		cancel()
		if err != nil {
			t.Fatal(err)
		}
	}
}

type budgetPacketSource struct {
	net.PacketConn
	size int
}

func (c budgetPacketSource) ReadFrom(b []byte) (int, net.Addr, error) {
	return min(c.size, len(b)), &net.UDPAddr{}, nil
}

func TestPacketReadChargesDeliveredBytesAndKeepsLimit(t *testing.T) {
	b := newByteBudgetProxy(netapi.NewErrProxy(net.ErrClosed), 250)
	c := &probeBudgetPacket{PacketConn: budgetPacketSource{size: 100}, b: b}
	buf := make([]byte, 65535)
	for range 2 {
		if n, _, err := c.ReadFrom(buf); n != 100 || err != nil {
			t.Fatal(n, err)
		}
	}
	if n, _, err := c.ReadFrom(buf); n != 0 || !errors.Is(err, errProbeByteBudget) {
		t.Fatal(n, err)
	}
}

func TestDefaultProbeScheduleRetainsRTTSampleThreshold(t *testing.T) {
	defaults := contract.MonitoringConfig{Probe: contract.ProbeSchedule{Enabled: true}}.Effective()
	selector := contract.Selector{Name: "s", NodeID: "a", Policy: &contract.SelectorPolicy{Mode: "lowest_latency", Candidates: []contract.SelectorCandidate{{NodeID: "a", Enabled: true}}, Weights: contract.SelectorWeights{}}}
	p := policyWithMonitoringDefaults(selector, defaults).Policy.Effective()
	now := time.Now()
	var h contract.ChannelHealth
	for i := range 5 {
		h.Samples = append([]contract.HealthSample{{At: now.Add(-time.Duration(i) * 60200 * time.Millisecond).UnixMilli(), OK: true, Kind: "https", Target: p.LatencyTarget, RTTMS: 100}}, h.Samples...)
	}
	c := scoreCandidate(p, selectionInput{config: contract.SelectorCandidate{NodeID: "a", Enabled: true}, enabled: true, health: h}, now)
	if !c.Eligible || c.Samples < 3 {
		t.Fatal(c.Reason, c.Samples)
	}
}

func TestSelectorEvidenceValidation(t *testing.T) {
	candidate := []contract.SelectorCandidate{{NodeID: "a", Enabled: true}}
	on := contract.MonitoringConfig{Probe: contract.ProbeSchedule{Enabled: true}}.Effective()
	for _, tc := range []struct {
		name   string
		policy contract.SelectorPolicy
		nodeID string
		ok     bool
	}{
		{"derived window", contract.SelectorPolicy{Mode: "lowest_latency"}, "a", true},
		{"window too short", contract.SelectorPolicy{Mode: "lowest_latency", MaxAgeMS: 60_000}, "a", false},
		{"short window without RTT", contract.SelectorPolicy{Mode: "failover", MaxAgeMS: 60_000}, "a", true},
		{"selected candidate", contract.SelectorPolicy{Mode: "failover", Fallback: "selected"}, "a", true},
		{"selected outside candidates", contract.SelectorPolicy{Mode: "failover", Fallback: "selected"}, "b", false},
		{"locked is exempt", contract.SelectorPolicy{Mode: "lowest_latency", Locked: true, MaxAgeMS: 60_000}, "a", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.policy.Candidates = candidate
			err := validateSelectorEvidence(contract.Selector{Name: "s", NodeID: tc.nodeID, Policy: &tc.policy}, on)
			if (err == nil) != tc.ok {
				t.Fatal(err)
			}
		})
	}
}

func TestSelectorEvidenceGap(t *testing.T) {
	off := contract.MonitoringConfig{}.Effective()
	on := contract.MonitoringConfig{Probe: contract.ProbeSchedule{Enabled: true}}.Effective()
	speed := on
	speed.Speed.Enabled, speed.Speed.Test.URL = true, "https://speed.example/file"
	for _, tc := range []struct {
		name     string
		policy   contract.SelectorPolicy
		defaults contract.MonitoringConfig
		gap      bool
	}{
		{"failover learns passively", contract.SelectorPolicy{Mode: "failover"}, off, false},
		{"latency without probes", contract.SelectorPolicy{Mode: "lowest_latency"}, off, true},
		{"latency with probes", contract.SelectorPolicy{Mode: "lowest_latency"}, on, false},
		{"selected fallback keeps traffic", contract.SelectorPolicy{Mode: "lowest_latency", Fallback: "selected"}, off, false},
		{"throughput without schedule", contract.SelectorPolicy{Mode: "highest_throughput"}, on, true},
		{"throughput with schedule", contract.SelectorPolicy{Mode: "highest_throughput"}, speed, false},
		{"default balanced needs speed", contract.SelectorPolicy{Mode: "balanced"}, on, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if gap := selectorEvidenceGap(contract.Selector{Policy: &tc.policy}, tc.defaults); (gap != "") != tc.gap {
				t.Fatal(gap)
			}
		})
	}
}

func TestPassiveSelectorDoesNotLockItselfOutWhenIdle(t *testing.T) {
	now := time.Now()
	policy := contract.SelectorPolicy{Mode: "failover", Candidates: []contract.SelectorCandidate{{NodeID: "a", Enabled: true}}}
	selector := policyWithMonitoringDefaults(contract.Selector{NodeID: "a", Policy: &policy}, contract.MonitoringConfig{}.Effective())
	inputs := []selectionInput{{config: policy.Candidates[0], enabled: true}}
	if d := evaluateSelector(selector, inputs, contract.SelectorDecision{}, now); d.NodeID != "a" || d.Reason != "fallback_unknown" {
		t.Fatal("idle selector cannot regain passive evidence", d)
	}
	inputs[0].circuit = &contract.CircuitStatus{State: "open"}
	if d := evaluateSelector(selector, inputs, contract.SelectorDecision{}, now); d.NodeID != "" {
		t.Fatal("open circuit admitted", d)
	}
	active := policyWithMonitoringDefaults(contract.Selector{NodeID: "a", Policy: &policy}, contract.MonitoringConfig{Probe: contract.ProbeSchedule{Enabled: true}}.Effective())
	inputs[0].circuit = nil
	if d := evaluateSelector(active, inputs, contract.SelectorDecision{}, now); d.NodeID != "" {
		t.Fatal("explicit reject ignored while probes provide evidence", d)
	}
}

func TestPeriodicThroughputQualifiesWithOneSample(t *testing.T) {
	now := time.Now()
	schedule := contract.SpeedSchedule{Enabled: true, IntervalMS: 3_600_000, Test: contract.SpeedTestRequest{URL: "https://speed.example/file"}}.Effective()
	p := contract.SelectorPolicy{SpeedTarget: schedule.Test.URL}.Effective()
	m := contract.ThroughputMeasurement{OK: true, At: now.Add(-time.Hour).UnixMilli(), Samples: 1, Target: schedule.Test.URL, DownloadMbps: 10}
	if freshThroughput(m, p.SpeedTarget, "download", p, now) {
		t.Fatal("without a schedule the policy thresholds must apply")
	}
	if !freshThroughput(m, p.SpeedTarget, "download", periodicThroughputRule(schedule, nil).apply(p), now) {
		t.Fatal("result of a periodic test expired before the next run")
	}
	m.At = now.Add(-3 * time.Hour).UnixMilli()
	if freshThroughput(m, p.SpeedTarget, "download", periodicThroughputRule(schedule, nil).apply(p), now) {
		t.Fatal("stale periodic result qualified")
	}
}

func TestNeutralProbeErrors(t *testing.T) {
	for _, err := range []error{context.Canceled, errNodeReconfigured, errors.ErrUnsupported, latency.ErrProbeRedirect} {
		if !neutralProbeError(err) {
			t.Fatal(err)
		}
	}
	for _, err := range []error{http.ErrHandlerTimeout, errors.New("auth failed"), net.ErrClosed} {
		if neutralProbeError(err) {
			t.Fatal(err)
		}
	}
}

func TestLazyConnectCannotHideFailingProbe(t *testing.T) {
	rules := circuitRules{failures: 3, recovery: 2, minSamples: 3, failureRate: .5, maxAge: 2 * time.Minute, cooldown: time.Minute, trialTimeout: time.Minute, concurrency: 1, maxRequests: 4}
	b := newCircuitBreaker(rules, nil)
	n := new(nodeCounters)
	n.setCircuitListeners(&nodeCircuitListeners{tcp: []*circuitBreaker{b}})
	for range 3 {
		n.remoteEvidence(true, contract.HealthSample{Kind: "https", OK: false}, context.DeadlineExceeded)
		for range 3 {
			n.remoteEvidence(true, contract.HealthSample{Kind: "connect", OK: true}, nil)
		}
	}
	if state := b.snapshot(time.Now()).State; state != "open" || n.tcpHealth.ConsecutiveFailures != 3 {
		t.Fatal(state, n.tcpHealth.ConsecutiveFailures)
	}
}

func TestServerResponseRestoresConnectEvidence(t *testing.T) {
	n := new(nodeCounters)
	n.remoteEvidence(true, contract.HealthSample{Kind: "https", OK: false}, context.DeadlineExceeded)
	n.remoteEvidence(true, contract.HealthSample{Kind: "response", OK: true}, nil)
	n.remoteEvidence(true, contract.HealthSample{Kind: "connect", OK: true}, nil)
	if n.tcpHealth.ConsecutiveFailures != 0 {
		t.Fatal(n.tcpHealth.ConsecutiveFailures)
	}
}

func TestSelectionOrderPrefersEligibleAndSkipsUnavailable(t *testing.T) {
	selector := contract.Selector{Policy: &contract.SelectorPolicy{Mode: "lowest_latency", Fallback: "priority_unknown"}}
	inputs := []selectionInput{
		{config: contract.SelectorCandidate{NodeID: "measured", Enabled: true, Priority: 9}, enabled: true},
		{config: contract.SelectorCandidate{NodeID: "unavailable", Enabled: true}, enabled: true, unavailableReason: "session_unavailable"},
		{config: contract.SelectorCandidate{NodeID: "unknown", Enabled: true, Priority: 1}, enabled: true},
	}
	d := contract.SelectorDecision{NodeID: "best", Candidates: []contract.SelectorCandidateStatus{{Eligible: true, RTTMS: 50, State: "healthy"}, {State: "unknown"}, {State: "unknown"}}}
	got := compileSelectionOrder(selector, inputs, d)
	if len(got) != 3 || got[0] != "best" || got[1] != "measured" || got[2] != "unknown" {
		t.Fatal(got)
	}
}

type scriptedProbeProxy struct {
	netapi.Proxy
	delay time.Duration
	err   error
}

func (p scriptedProbeProxy) Conn(ctx context.Context, _ netapi.Address) (net.Conn, error) {
	select {
	case <-time.After(p.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if p.err != nil {
		return nil, p.err
	}
	local, remote := net.Pipe()
	_ = remote.Close()
	return local, nil
}

func scriptedProbeRuntime(t *testing.T, proxy scriptedProbeProxy) (*NodeRuntime, contract.Node) {
	t.Helper()
	r := newTestRuntime(t)
	n, err := r.Save(t.Context(), testNode(t, "a", "a"))
	if err != nil {
		t.Fatal(err)
	}
	proxy.Proxy = netapi.NewErrProxy(net.ErrClosed)
	if _, err := r.proxies.LoadOrCreate(t.Context(), n.ID, func() (*ProxyEntry, error) { return &ProxyEntry{Proxy: proxy, Name: n.ID}, nil }); err != nil {
		t.Fatal(err)
	}
	return r, n
}

func TestScheduledProbeRecordsEOFAsFailure(t *testing.T) {
	r, n := scriptedProbeRuntime(t, scriptedProbeProxy{err: io.ErrUnexpectedEOF})
	options := contract.ProbeSchedule{Enabled: true, TimeoutMS: 1000}.Effective()
	if err := r.selectors.runProbe(t.Context(), n, options, contract.LatencyRequest{Type: "tcp_connect", Host: "192.0.2.1:443"}); err == nil {
		t.Fatal("probe succeeded")
	}
	h := r.observer.counter(n.ID).snapshot().TCPHealth
	if h.ConsecutiveFailures != 1 || len(h.Samples) != 1 || h.Samples[0].OK {
		t.Fatal(h)
	}
}

func TestBudgetWaitDoesNotConsumeProbeTimeout(t *testing.T) {
	r, n := scriptedProbeRuntime(t, scriptedProbeProxy{delay: 400 * time.Millisecond})
	r.selectors.mu.Lock()
	// Refill in 500 ms: wait plus probe exceed the timeout, each alone does not.
	r.selectors.probeLimiter = rate.NewLimiter(rate.Limit(2*probeByteBudget), int(probeByteBudget))
	r.selectors.probeLimiter.AllowN(time.Now(), int(probeByteBudget))
	r.selectors.mu.Unlock()
	options := contract.ProbeSchedule{Enabled: true, TimeoutMS: 700}.Effective()
	ctx, cancel := context.WithTimeout(t.Context(), 1400*time.Millisecond)
	defer cancel()
	if err := r.selectors.runProbe(ctx, n, options, contract.LatencyRequest{Type: "tcp_connect", Host: "192.0.2.1:443"}); err != nil {
		t.Fatal(err)
	}
	if h := r.observer.counter(n.ID).snapshot().TCPHealth; h.ConsecutiveFailures != 0 || h.ConsecutiveSuccesses != 1 {
		t.Fatal(h)
	}
}
