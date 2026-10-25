package node

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func metricFamily(t *testing.T, reg *prometheus.Registry, name string) *dto.MetricFamily {
	t.Helper()
	values, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range values {
		if v.GetName() == name {
			return v
		}
	}
	t.Fatalf("missing metric %s", name)
	return nil
}
func TestOutboundMetricsBoundedLabelsAndUnits(t *testing.T) {
	r := NewNodeRuntime(t.TempDir() + "/unused.db")
	defer r.Close()
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(r.Metrics())
	for i := range 1000 {
		r.metrics.observeProbe(fmt.Sprintf("target-%d.example", i), true, nil, 25*time.Millisecond)
	}
	r.metrics.observeProbe("https", true, nil, 50*time.Millisecond)
	r.metrics.observeProbe("https", false, context.Canceled, 0)
	v := metricFamily(t, reg, "yuhaiin_outbound_probes_total")
	if len(v.Metric) != 3 {
		t.Fatal("unbounded probe kind labels", len(v.Metric))
	}
	h := metricFamily(t, reg, "yuhaiin_outbound_probe_rtt_seconds")
	for _, m := range h.Metric {
		if m.Label[0].GetValue() == "https" && m.GetHistogram().GetSampleSum() != .05 {
			t.Fatal("RTT not in seconds", m)
		}
	}
	r.metrics.observeSpeed(contract.ThroughputMeasurement{At: 1000, OK: true, DownloadMbps: 12}, nil)
	r.metrics.observeSpeed(contract.ThroughputMeasurement{}, errSpeedBusy)
	if v := metricFamily(t, reg, "yuhaiin_outbound_last_speed_timestamp_seconds").Metric[0].GetGauge().GetValue(); v != 1 {
		t.Fatal("rejected test replaced latest result", v)
	}
	r.metrics.observeSpeed(contract.ThroughputMeasurement{At: 2000, OK: true, DownloadMbps: 99}, context.Canceled)
	if v := metricFamily(t, reg, "yuhaiin_outbound_last_speed_success").Metric[0].GetGauge().GetValue(); v != 0 {
		t.Fatal("cancelled test marked successful", v)
	}
	h = metricFamily(t, reg, "yuhaiin_outbound_active_download_mbps")
	if h.Metric[0].GetHistogram().GetSampleCount() != 1 || h.Metric[0].GetHistogram().GetSampleSum() != 12 {
		t.Fatal("speed histogram included skipped/cancelled data", h)
	}
	if _, err := os.Stat(r.path); !os.IsNotExist(err) {
		t.Fatal("cold scrape opened SQLite", err)
	}
}

func TestOutboundMetricsScrapeNeverNeedsSQLiteAndSurvivesDelete(t *testing.T) {
	r := newTestRuntime(t)
	if _, err := r.Save(t.Context(), testNode(t, "a", "a")); err != nil {
		t.Fatal(err)
	}
	svc := NewSelectorService(r)
	s, err := svc.Save(t.Context(), contract.Selector{Name: "s", NodeID: "a"})
	if err != nil {
		t.Fatal(err)
	}
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(r.Metrics())
	lease, err := r.sqlite.DB().Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := reg.Gather(); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(time.Second):
		t.Error("metrics queried SQLite")
	}
	_ = lease.Close()
	// Scrapes race with snapshot publication and metric observation.
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 100 {
			if _, err := reg.Gather(); err != nil {
				t.Error(err)
			}
		}
	})
	for range 20 {
		s.Name += "x"
		s, err = svc.Save(t.Context(), s)
		if err != nil {
			t.Fatal(err)
		}
		r.metrics.observeProbe("tcp_connect", true, nil, time.Millisecond)
	}
	wg.Wait()
	if err := svc.Delete(t.Context(), s.ID); err != nil {
		t.Fatal(err)
	}
	if v := metricFamily(t, reg, "yuhaiin_outbound_probes_total").Metric[0].GetCounter().GetValue(); v != 20 {
		t.Fatal("deletion reset counter", v)
	}
	for _, v := range []string{"https://attacker.example", "arbitrary-user-id", "arbitrary-domain"} {
		if metricReason(v) != "other" || metricMode(v) != "other" {
			t.Fatal("user value accepted as metric label")
		}
	}
}
