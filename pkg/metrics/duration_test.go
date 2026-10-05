package metrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func TestLatencyMetricsUseSeconds(t *testing.T) {
	registry := prometheus.NewRegistry()
	p := newPrometheus(registry)
	p.AddStreamConnectDuration(250 * time.Millisecond)
	p.AddDnsQueryDuration("test", 125*time.Millisecond)
	p.AddTrieMatchDuration(75 * time.Microsecond)
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	wants := map[string]struct{ sum, bucket float64 }{
		"yuhaiin_stream_connect_duration_seconds": {0.25, 0.3},
		"yuhaiin_stream_connect_summary_seconds":  {0.25, 0},
		"yuhaiin_dns_query_duration_seconds":      {0.125, 0.2},
		"yuhaiin_trie_match_duration_seconds":     {0.000075, 0.0001},
	}
	for _, family := range families {
		want, ok := wants[family.GetName()]
		if !ok {
			continue
		}
		delete(wants, family.GetName())
		for _, metric := range family.GetMetric() {
			if h := metric.GetHistogram(); h != nil {
				if h.GetSampleCount() != 1 || h.GetSampleSum() != want.sum {
					t.Fatalf("%s count/sum=%d/%g", family.GetName(), h.GetSampleCount(), h.GetSampleSum())
				}
				found := false
				for _, bucket := range h.GetBucket() {
					if bucket.GetUpperBound() == want.bucket {
						found = true
						if bucket.GetCumulativeCount() != 1 {
							t.Fatalf("%s bucket=%v", family.GetName(), bucket)
						}
					}
				}
				if !found {
					t.Fatalf("%s lacks seconds bucket %g", family.GetName(), want.bucket)
				}
			} else if s := metric.GetSummary(); s != nil {
				if s.GetSampleCount() != 1 || s.GetSampleSum() != want.sum {
					t.Fatalf("compatibility summary=%v", s)
				}
			} else {
				t.Fatalf("unexpected metric %v", metric)
			}
		}
	}
	if len(wants) != 0 {
		t.Fatalf("missing metrics %v", wants)
	}
}

func BenchmarkObserveLatency(b *testing.B) {
	p := newPrometheus(prometheus.NewRegistry())
	b.Run("Connect", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			p.AddStreamConnectDuration(250 * time.Millisecond)
		}
	})
	b.Run("DNS", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			p.AddDnsQueryDuration("test", 125*time.Millisecond)
		}
	})
	b.Run("Route", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			p.AddTrieMatchDuration(75 * time.Microsecond)
		}
	})
}
