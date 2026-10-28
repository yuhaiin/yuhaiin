package manager

import (
	"slices"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/certificate"
	"github.com/prometheus/client_golang/prometheus"
)

type metricResource struct {
	state  string
	expiry int64
}
type metricSnapshot struct{ resources []metricResource }

func (m *Manager) Events() []contract.Event {
	m.eventMu.Lock()
	defer m.eventMu.Unlock()
	return slices.Clone(m.events)
}

func (m *Manager) publishMetrics(resources []contract.Resource) {
	values := make([]metricResource, 0, len(resources))
	for _, r := range resources {
		expiry := int64(0)
		if !r.Status.NotAfter.IsZero() {
			expiry = r.Status.NotAfter.Unix()
		}
		values = append(values, metricResource{r.Status.State, expiry})
	}
	m.metricSnapshot.Store(&metricSnapshot{values})
}

type collector struct {
	owner                        *Manager
	states, expiration, renewals *prometheus.Desc
}

func (m *Manager) Metrics() prometheus.Collector {
	return &collector{m,
		prometheus.NewDesc("yuhaiin_certificates", "Managed site certificates by lifecycle state.", []string{"state"}, nil),
		prometheus.NewDesc("yuhaiin_certificate_expiration_min_seconds", "Shortest remaining managed site certificate lifetime, or zero when none is issued.", nil, nil),
		prometheus.NewDesc("yuhaiin_certificate_renewals_total", "Completed certificate issuance/renewal attempts.", []string{"result"}, nil)}
}
func (c *collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.states
	ch <- c.expiration
	ch <- c.renewals
}
func (c *collector) Collect(ch chan<- prometheus.Metric) {
	counts := map[string]int{}
	minimum := int64(0)
	hasCertificate := false
	now := time.Now().Unix()
	if snapshot := c.owner.metricSnapshot.Load(); snapshot != nil {
		for _, resource := range snapshot.resources {
			state := resource.state
			if resource.expiry > 0 {
				remaining := resource.expiry - now
				if !hasCertificate || remaining < minimum {
					minimum = remaining
					hasCertificate = true
				}
				if remaining <= 0 {
					state = "expired"
				}
			}
			if !slices.Contains([]string{"queued", "issuing", "ready", "failed", "expired", "disabled"}, state) {
				state = "unknown"
			}
			counts[state]++
		}
	}
	for _, state := range []string{"queued", "issuing", "ready", "failed", "expired", "disabled", "unknown"} {
		ch <- prometheus.MustNewConstMetric(c.states, prometheus.GaugeValue, float64(counts[state]), state)
	}
	ch <- prometheus.MustNewConstMetric(c.expiration, prometheus.GaugeValue, float64(minimum))
	ch <- prometheus.MustNewConstMetric(c.renewals, prometheus.CounterValue, float64(c.owner.successes.Load()), "success")
	ch <- prometheus.MustNewConstMetric(c.renewals, prometheus.CounterValue, float64(c.owner.failures.Load()), "failure")
}
