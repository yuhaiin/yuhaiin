package node

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/prometheus/client_golang/prometheus"
)

// No user-controlled identities/targets enter these label domains. Detailed
// per-resource evidence remains in the bounded existing management APIs.
func metricMode(mode string) string {
	switch mode {
	case "manual", "failover", "lowest_latency", "highest_throughput", "balanced", "weighted":
		return mode
	default:
		return "other"
	}
}
func metricReason(reason string) string {
	switch reason {
	case "manual", "manual_lock", "failover", "lowest_latency", "highest_throughput", "balanced", "weighted", "no_healthy_candidate", "fallback_selected", "fallback_unknown", "hold_or_cooldown", "latency_hysteresis", "score_hysteresis", "throughput_hysteresis", "sticky_failover", "selected_node_unavailable":
		return reason
	default:
		return "other"
	}
}
func metricProbeKind(kind string) string {
	switch kind {
	case "tcp", "http", "https", "tcp_connect", "udp", "dns", "doq", "stun", "stun_tcp", "ip", "native":
		return kind
	default:
		return "other"
	}
}
func measurementOutcome(err error, ok bool) string {
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	if errors.Is(err, errMeasurementBusy) || errors.Is(err, errProbeSkipped) || errors.Is(err, errProbeByteBudget) || errors.Is(err, errSpeedBusy) || errors.Is(err, errSpeedBudget) || localProbeDenial(err) {
		return "skipped"
	}
	if err != nil || !ok {
		return "failure"
	}
	return "success"
}

type reliabilityMetrics struct {
	probes, speed, uploadTests, switches, suppressed *prometheus.CounterVec
	rtt                                              *prometheus.HistogramVec
	download, upload                                 prometheus.Histogram
	latestUpload                                     atomic.Pointer[contract.ThroughputMeasurement]
	latestSpeed                                      atomic.Pointer[contract.ThroughputMeasurement]
}

func newReliabilityMetrics() *reliabilityMetrics {
	counter := func(name, help string, labels ...string) *prometheus.CounterVec {
		return prometheus.NewCounterVec(prometheus.CounterOpts{Name: "yuhaiin_outbound_" + name, Help: help}, labels)
	}
	return &reliabilityMetrics{
		uploadTests: counter("upload_tests_total", "Manual/scheduled opt-in active upload test outcomes.", "outcome"),
		probes:      counter("probes_total", "Completed manual/scheduled probe outcomes, including local skips.", "kind", "outcome"),
		speed:       counter("speed_tests_total", "Manual/scheduled active download test outcomes.", "outcome"),
		switches:    counter("selector_switches_total", "Compiled selector changes after initial selection.", "network", "mode", "reason"),
		suppressed:  counter("selector_suppressed_total", "Decision evaluations retaining the current choice due to hysteresis/hold rules.", "network", "mode", "reason"),
		rtt:         prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "yuhaiin_outbound_probe_rtt_seconds", Help: "Successful complete probe duration excluding admission/bandwidth wait.", Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 15, 30}}, []string{"kind"}),
		upload:      prometheus.NewHistogram(prometheus.HistogramOpts{Name: "yuhaiin_outbound_active_upload_mbps", Help: "Successful target/time-specific active upload measurements acknowledged by the configured endpoint; not business Bps or capacity guarantees.", Buckets: []float64{1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500}}),
		download:    prometheus.NewHistogram(prometheus.HistogramOpts{Name: "yuhaiin_outbound_active_download_mbps", Help: "Successful target/time-specific active download measurements, including applied traffic limits; not business Bps or capacity guarantees.", Buckets: []float64{1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500}}),
	}
}
func (m *reliabilityMetrics) observeProbe(kind string, ok bool, err error, duration time.Duration) {
	outcome := measurementOutcome(err, ok)
	kind = metricProbeKind(kind)
	m.probes.WithLabelValues(kind, outcome).Inc()
	if outcome == "success" && duration > 0 {
		m.rtt.WithLabelValues(kind).Observe(duration.Seconds())
	}
}
func (m *reliabilityMetrics) observeSpeed(value contract.ThroughputMeasurement, err error) {
	if value.Direction == "upload" {
		m.uploadTests.WithLabelValues(measurementOutcome(err, value.OK)).Inc()
		if value.At == 0 {
			return
		}
		value.OK = err == nil && value.OK
		m.latestUpload.Store(new(value))
		if value.OK {
			m.upload.Observe(value.UploadMbps)
		}
		return
	}
	m.speed.WithLabelValues(measurementOutcome(err, value.OK)).Inc()
	if value.At == 0 {
		return
	} // A rejected reservation did not perform a test.
	value.OK = err == nil && value.OK
	m.latestSpeed.Store(new(value))
	if err == nil && value.OK {
		m.download.Observe(value.DownloadMbps)
	}
}
func (m *reliabilityMetrics) collectors() []prometheus.Collector {
	return []prometheus.Collector{m.probes, m.speed, m.switches, m.suppressed, m.rtt, m.download, m.uploadTests, m.upload}
}

type decisionMetricKey struct{ network, mode, reason string }
type selectionMetricSnapshot struct {
	decisions map[decisionMetricKey]int
	circuits  [2][3]int
}

func (s *selectorRuntime) compileMetrics(next *selectorSnapshot) {
	v := selectionMetricSnapshot{decisions: make(map[decisionMetricKey]int)}
	for _, p := range next.items {
		mode := "manual"
		if p.config.Policy != nil {
			mode = p.config.Policy.Effective().Mode
		}
		for i, d := range []contract.SelectorDecision{p.status.TCP, p.status.UDP} {
			network := "tcp"
			if i == 1 {
				network = "udp"
			}
			v.decisions[decisionMetricKey{network, metricMode(mode), metricReason(d.Reason)}]++
		}
	}
	for key, b := range s.breakers {
		i := 0
		if !key.tcp {
			i = 1
		}
		state := b.state.Load()
		if state <= circuitHalfOpen {
			v.circuits[i][state]++
		}
	}
	next.metrics = v
}

type outboundCollector struct {
	lastUploadOK, lastUploadAt, lastUploadMbps                           *prometheus.Desc
	runtime                                                              *NodeRuntime
	decisions, circuits, active, limit, policy, lastOK, lastAt, lastMbps *prometheus.Desc
}

// Metrics joins the existing endpoint. Scrapes use immutable runtime snapshots,
// never SQLite or fresh network work; counters survive resource deletion.
func (r *NodeRuntime) Metrics() prometheus.Collector {
	desc := func(name, help string, labels ...string) *prometheus.Desc {
		return prometheus.NewDesc("yuhaiin_outbound_"+name, help, labels, nil)
	}
	return &outboundCollector{runtime: r,
		decisions:      desc("selector_decisions", "Configured selector count per current decision; identities are available through the management API.", "network", "mode", "reason"),
		circuits:       desc("circuits", "Unique shared circuit instances per channel/state (different threshold policies may own different instances).", "network", "state"),
		active:         desc("measurements_active", "Manual and periodic measurements currently admitted, including local bandwidth wait."),
		limit:          desc("measurement_limit", "Configured shared measurement admission limit."),
		policy:         desc("measurement_policy", "Measurement policy scope, one for the current state and zero for others.", "state"),
		lastUploadOK:   desc("last_upload_success", "One if the latest completed active upload test succeeded."),
		lastUploadAt:   desc("last_upload_timestamp_seconds", "Timestamp of the latest completed active upload test."),
		lastUploadMbps: desc("last_measured_upload_mbps", "Latest acknowledged measured upload Mbps; check success/timestamp before use."),
		lastOK:         desc("last_speed_success", "One if the latest completed active speed test succeeded."),
		lastAt:         desc("last_speed_timestamp_seconds", "Timestamp of the latest completed active speed test (not a capacity freshness guarantee)."),
		lastMbps:       desc("last_measured_download_mbps", "Latest completed active measured download Mbps; check success/timestamp before use."),
	}
}
func (c *outboundCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, collector := range c.runtime.metrics.collectors() {
		collector.Describe(ch)
	}
	for _, d := range []*prometheus.Desc{c.decisions, c.circuits, c.active, c.limit, c.policy, c.lastOK, c.lastAt, c.lastMbps, c.lastUploadOK, c.lastUploadAt, c.lastUploadMbps} {
		ch <- d
	}
}
func (c *outboundCollector) Collect(ch chan<- prometheus.Metric) {
	r := c.runtime
	for _, collector := range r.metrics.collectors() {
		collector.Collect(ch)
	}
	emit := func(d *prometheus.Desc, value float64, labels ...string) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, value, labels...)
	}
	emit(c.active, float64(r.measurementActive.Load()))
	emit(c.limit, float64(r.measurementLimit.Load()))
	scope := r.probePolicyState()
	for _, state := range []string{"waiting", "enforced", "standalone"} {
		v := 0.
		if state == scope {
			v = 1
		}
		emit(c.policy, v, state)
	}
	if latest := r.metrics.latestSpeed.Load(); latest != nil {
		ok := 0.
		if latest.OK {
			ok = 1
		}
		emit(c.lastOK, ok)
		emit(c.lastAt, float64(latest.At)/1000)
		emit(c.lastMbps, latest.DownloadMbps)
	}
	if latest := r.metrics.latestUpload.Load(); latest != nil {
		ok := 0.
		if latest.OK {
			ok = 1
		}
		emit(c.lastUploadOK, ok)
		emit(c.lastUploadAt, float64(latest.At)/1000)
		emit(c.lastUploadMbps, latest.UploadMbps)
	}

	r.mu.Lock()
	s := r.selectors
	closed := r.closed
	r.mu.Unlock()
	if s == nil || closed {
		return
	}
	snapshot := s.snapshot.Load()
	if snapshot == nil {
		return
	}
	for key, count := range snapshot.metrics.decisions {
		emit(c.decisions, float64(count), key.network, key.mode, key.reason)
	}
	for i, network := range []string{"tcp", "udp"} {
		for state, name := range []string{"closed", "open", "half_open"} {
			emit(c.circuits, float64(snapshot.metrics.circuits[i][state]), network, name)
		}
	}
}
