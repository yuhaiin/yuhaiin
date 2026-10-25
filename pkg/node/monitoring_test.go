package node

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

func TestMobileAndMeteredMonitoringDefaults(t *testing.T) {
	for _, tc := range []struct {
		platform              string
		network               contract.MonitoringNetworkState
		mobile, metered, want bool
	}{
		{"android", contract.MonitoringNetworkState{Online: true}, false, false, false},
		{"android", contract.MonitoringNetworkState{Online: true}, true, false, false},
		{"android", contract.MonitoringNetworkState{Online: true, Foreground: true}, true, false, true},
		{"linux", contract.MonitoringNetworkState{Online: true, Metered: true}, false, false, false},
		{"linux", contract.MonitoringNetworkState{Online: true, Metered: true}, false, true, true},
		{"linux", contract.MonitoringNetworkState{}, true, true, false},
	} {
		if got := monitoringAllowed(tc.platform, tc.network, tc.mobile, tc.metered); got != tc.want {
			t.Fatal(tc, got)
		}
	}
	if c := (contract.MonitoringConfig{}).Effective(); c.Probe.Enabled || c.Speed.Enabled {
		t.Fatal("periodic traffic enabled by default")
	}
}
func TestMonitoringPersistenceSharingAndNetworkReschedule(t *testing.T) {
	r := newTestRuntime(t)
	if _, err := r.Save(t.Context(), testNode(t, "a", "a")); err != nil {
		t.Fatal(err)
	}
	svc := NewSelectorService(r)
	for _, name := range []string{"one", "two"} {
		_, err := svc.Save(t.Context(), contract.Selector{Name: name, NodeID: "a", Policy: &contract.SelectorPolicy{Mode: "failover", Candidates: []contract.SelectorCandidate{{NodeID: "a", Enabled: true, Weight: 1}}}})
		if err != nil {
			t.Fatal(err)
		}
	}
	status, err := r.Monitoring(t.Context())
	if err != nil || status.Jobs != 0 || status.Workers != 0 {
		t.Fatal(status, err)
	}
	c := status.Config
	c.Probe.Enabled = true
	c.Probe.NetworkCostPolicy = "cached_only"
	status, err = r.SaveMonitoring(t.Context(), c)
	if err != nil || status.Jobs != 2 || status.Workers > 4 {
		t.Fatal("shared node probes not deduplicated", status, err)
	}
	status, err = r.SetMonitoringNetworkState(t.Context(), contract.MonitoringNetworkState{Online: false})
	if err != nil || status.Jobs != 0 {
		t.Fatal(status, err)
	}
	generation := status.Network.Generation
	status, err = r.SetMonitoringNetworkState(t.Context(), contract.MonitoringNetworkState{Online: true, Foreground: true})
	if err != nil || status.Jobs != 2 || status.Network.Generation <= generation {
		t.Fatal(status, err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	next := NewNodeRuntime(r.path)
	defer next.Close()
	status, err = next.Monitoring(t.Context())
	if err != nil || !status.Config.Probe.Enabled || status.Jobs != 2 {
		t.Fatal("settings lost on restart", status, err)
	}
}
func TestSelectorCanDisableInheritedProbes(t *testing.T) {
	r := newTestRuntime(t)
	if _, err := r.Save(t.Context(), testNode(t, "a", "a")); err != nil {
		t.Fatal(err)
	}
	svc := NewSelectorService(r)
	s, err := svc.Save(t.Context(), contract.Selector{Name: "Override", NodeID: "a", Policy: &contract.SelectorPolicy{Mode: "failover", Candidates: []contract.SelectorCandidate{{NodeID: "a", Enabled: true}}}})
	if err != nil {
		t.Fatal(err)
	}
	c := contract.MonitoringConfig{Probe: contract.ProbeSchedule{Enabled: true, Kinds: []string{"tcp_connect"}, NetworkCostPolicy: "cached_only"}}
	if _, err := r.SaveMonitoring(t.Context(), c); err != nil {
		t.Fatal(err)
	}
	s.Policy.Probe = &contract.ProbeSchedule{Enabled: false}
	if _, err := svc.Save(t.Context(), s); err != nil {
		t.Fatal(err)
	}
	status, err := r.Monitoring(t.Context())
	if err != nil || status.Jobs != 0 {
		t.Fatal(status, err)
	}
}
func TestScheduledConnectUsesActualNodeAndSeparateEvidence(t *testing.T) {
	r := newTestRuntime(t)
	if _, err := r.Save(t.Context(), testNode(t, "a", "a")); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_ = c.Close()
			close(accepted)
		}
	}()
	n := testNode(t, "a", "a")
	options := contract.ProbeSchedule{}.Effective()
	if err := r.selectors.runProbe(t.Context(), n, options, contract.LatencyRequest{Type: "tcp_connect", Host: ln.Addr().String()}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("target node did not connect")
	}
	stats := r.observer.counter("a").snapshot()
	if !stats.Probes["tcp_connect"].Result.OK || len(stats.UDPHealth.Samples) != 0 || len(stats.TCPHealth.LatencySamples) != 0 {
		t.Fatal(stats)
	}
}
func TestPeriodicWorkDoesNotStartEnterpriseAuthentication(t *testing.T) {
	r := newTestRuntime(t)
	if _, err := r.Save(t.Context(), testNode(t, "a", "a")); err != nil {
		t.Fatal(err)
	}
	n := testNode(t, "a", "a")
	n.Chain = []contract.Protocol{{Type: "openvpn", OpenVPN: &contract.OpenVPN{Gateway: "vpn.invalid:443"}}}
	for _, policy := range []string{"conservative", "cached_only", "allow_expensive"} {
		if r.selectors.probeCanStart(n, policy) {
			t.Fatal("periodic job would start VPN login", policy)
		}
	}
	if _, err := r.proxies.LoadOrCreate(t.Context(), "a", func() (*ProxyEntry, error) {
		return &ProxyEntry{Proxy: netapi.NewErrProxy(errors.New("cached offline client"))}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if !r.selectors.probeCanStart(n, "conservative") {
		t.Fatal("existing VPN client cannot be probed")
	}
}
func TestProbeByteBudgetIsSharedAcrossConnections(t *testing.T) {
	b := newProbeBudgetProxy(netapi.NewErrProxy(errors.New("unused")))
	total := 0
	for range 100 {
		total += b.claim(1000)
	}
	if total != int(probeByteBudget) || b.remaining.Load() != 0 {
		t.Fatal(total, b.remaining.Load())
	}
	if got := b.claim(1); got != 0 {
		t.Fatal(got)
	}
}
func TestConstructorFailureAndCancellationAreDifferentEvidence(t *testing.T) {
	c := new(nodeCounters)
	c.constructionFailure(context.Canceled)
	if len(c.snapshot().TCPHealth.Samples) > 0 {
		t.Fatal("cancel counted")
	}
	for range 3 {
		c.constructionFailure(errors.New("VPN startup failed"))
	}
	v := c.snapshot()
	if v.TCPHealth.State != "unhealthy" || v.UDPHealth.State != "unhealthy" || v.TCPHealth.Samples[0].Kind != "construction" {
		t.Fatal(v)
	}
}

func TestNetworkNotificationsKeepNewestInterfaceState(t *testing.T) {
	r := newTestRuntime(t)
	if _, err := r.Save(t.Context(), testNode(t, "a", "a")); err != nil {
		t.Fatal(err)
	}
	s := r.selectors
	// Exercise the coalesced callback while the consumer cannot take its lock.
	s.mu.Lock()
	s.interfaceChanged("")
	s.interfaceChanged("eth-test")
	s.mu.Unlock()
	s.reconcileInterface()
	status, err := r.Monitoring(t.Context())
	if err != nil || !status.Network.Online || status.Network.Generation == 0 {
		t.Fatal(status, err)
	}
}
func TestMonitoringRejectsInvalidTargetsAndUnboundedTests(t *testing.T) {
	for _, c := range []contract.MonitoringConfig{
		{Probe: contract.ProbeSchedule{Concurrency: 17}},
		{Probe: contract.ProbeSchedule{IntervalMS: 1}},
		{Probe: contract.ProbeSchedule{LatencyTarget: "http://example.com"}},
		{Probe: contract.ProbeSchedule{DNSAddress: "localhost:99999"}},
		{Probe: contract.ProbeSchedule{DNSDomain: "invalid/domain"}},
		{Speed: contract.SpeedSchedule{Enabled: true, Test: contract.SpeedTestRequest{URL: "https://speed.example", MaxBytes: 65 << 20}}},
	} {
		if c.Validate() == nil {
			t.Fatal("accepted", c)
		}
	}
}

func TestMonitoringRevisionRejectsStaleSave(t *testing.T) {
	r := newTestRuntime(t)
	status, err := r.Monitoring(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	stale := status.Config
	saved, err := r.SaveMonitoring(t.Context(), stale)
	if err != nil || saved.Config.Revision != 1 {
		t.Fatal(saved, err)
	}
	if _, err := r.SaveMonitoring(t.Context(), stale); err == nil {
		t.Fatal("stale monitoring configuration accepted")
	}
}
