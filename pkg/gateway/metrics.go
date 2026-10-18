package gateway

import (
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type gatewayMetrics struct {
	manager                                                                      *Manager
	requests, blocked, forwarded, errors, tlsFailures, duration, healthy, active *prometheus.Desc
}

// Metrics shares the existing /metrics endpoint without adding work or label
// allocation to request processing. Backend labels omit path/query and secrets.
func (m *Manager) Metrics() prometheus.Collector {
	desc := func(name, help string, labels ...string) *prometheus.Desc {
		return prometheus.NewDesc("yuhaiin_gateway_"+name, help, labels, nil)
	}
	return &gatewayMetrics{manager: m,
		requests: desc("requests_total", "Admitted HTTP requests.", "gateway"), blocked: desc("blocked_total", "Blocked HTTP requests.", "gateway"), forwarded: desc("forwarded_total", "Forwarded HTTP requests.", "gateway"), errors: desc("errors_total", "HTTP upstream errors.", "gateway"), tlsFailures: desc("tls_failures_total", "MITM handshake or certificate failures.", "gateway"), duration: desc("request_duration_seconds_total", "Total completed HTTP request duration.", "gateway"), healthy: desc("backend_healthy", "Backend health, 1 if available.", "gateway", "upstream", "backend", "origin"), active: desc("backend_requests_active", "Active backend HTTP requests.", "gateway", "upstream", "backend", "origin")}
}
func (c *gatewayMetrics) Describe(ch chan<- *prometheus.Desc) {
	for _, desc := range []*prometheus.Desc{c.requests, c.blocked, c.forwarded, c.errors, c.tlsFailures, c.duration, c.healthy, c.active} {
		ch <- desc
	}
}
func (c *gatewayMetrics) Collect(ch chan<- prometheus.Metric) {
	s := c.manager.current.Load()
	for id, g := range s.gateways {
		counters := g.engine.Counters
		for _, value := range []struct {
			desc  *prometheus.Desc
			value float64
		}{{c.requests, float64(counters.Requests.Load())}, {c.blocked, float64(counters.Blocked.Load())}, {c.forwarded, float64(counters.Forwarded.Load())}, {c.errors, float64(counters.Errors.Load())}, {c.tlsFailures, float64(counters.TLSFailures.Load())}, {c.duration, float64(counters.DurationNS.Load()) / float64(time.Second)}} {
			ch <- prometheus.MustNewConstMetric(value.desc, prometheus.CounterValue, value.value, id)
		}
		for uid, u := range g.engine.upstreams {
			for n, b := range u.backends {
				healthy := float64(0)
				if b.unavailableUntil.Load() <= time.Now().UnixNano() {
					healthy = 1
				}
				labels := []string{id, uid, strconv.Itoa(n), b.url.Scheme + "://" + b.url.Host}
				ch <- prometheus.MustNewConstMetric(c.healthy, prometheus.GaugeValue, healthy, labels...)
				ch <- prometheus.MustNewConstMetric(c.active, prometheus.GaugeValue, float64(b.active.Load()), labels...)
			}
		}
	}
}
