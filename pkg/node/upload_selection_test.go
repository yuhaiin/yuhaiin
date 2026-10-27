package node

import (
	"fmt"
	"math"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
)

func TestUploadOnlyAndMixedBalancedSelection(t *testing.T) {
	now := time.Unix(10000, 0)
	s, inputs := selectionFixture(now)
	s.Policy.Mode, s.Policy.UploadTarget = "balanced", "https://upload.example/test"
	s.Policy.Weights = contract.SelectorWeights{Upload: 1, UploadReferenceMbps: 30}
	for i := range inputs {
		inputs[i].speed = contract.ThroughputMeasurement{}
		inputs[i].uploadSpeed = contract.ThroughputMeasurement{Direction: "upload", At: now.UnixMilli() - 100, OK: true, Samples: 3, Target: s.Policy.UploadTarget, UploadMbps: float64(10 + i*90)}
	}
	d := evaluateSelector(s, inputs, contract.SelectorDecision{}, now)
	if d.NodeID != "b" || d.Candidates[1].UploadSamples != 3 || d.Candidates[1].UploadAt != now.UnixMilli()-100 || d.Candidates[1].DownloadMbps != 0 {
		t.Fatalf("upload-only selection=%+v", d)
	}
	s.Policy.Weights.Download = 1
	if d := evaluateSelector(s, inputs, contract.SelectorDecision{}, now); d.NodeID != "" {
		t.Fatal("invented download samples", d)
	}
	for i := range inputs {
		inputs[i].speed = contract.ThroughputMeasurement{At: now.UnixMilli() - 100, OK: true, Samples: 3, Target: s.Policy.SpeedTarget, DownloadMbps: 100}
	}
	if d := evaluateSelector(s, inputs, contract.SelectorDecision{}, now); d.NodeID != "b" {
		t.Fatal("mixed selection", d)
	}
}
func TestUploadFreshnessAndProvenanceAreIndependent(t *testing.T) {
	now := time.Unix(10000, 0)
	for _, behavior := range []string{"expired", "unknown", "future", "target", "few_samples", "not_upload", "nan", "inf", "failed", "laundered_download"} {
		t.Run(behavior, func(t *testing.T) {
			s, inputs := selectionFixture(now)
			s.Policy.Mode, s.Policy.UploadTarget = "balanced", "https://upload.example/test"
			s.Policy.Weights = contract.SelectorWeights{Upload: 1, UploadReferenceMbps: 30}
			for i := range inputs {
				m := contract.ThroughputMeasurement{Direction: "upload", At: now.UnixMilli() - 100, OK: true, Samples: 3, Target: s.Policy.UploadTarget, UploadMbps: 100}
				switch behavior {
				case "expired":
					m.At = now.Add(-3 * time.Minute).UnixMilli()
				case "unknown":
					m.At = 0
				case "future":
					m.At = now.Add(time.Minute).UnixMilli()
				case "target":
					m.Target = "https://other.example/"
				case "few_samples":
					m.Samples = 1
				case "not_upload":
					m.Direction = ""
				case "nan":
					m.UploadMbps = math.NaN()
				case "inf":
					m.UploadMbps = math.Inf(1)
				case "failed":
					m.OK = false
				case "laundered_download":
					inputs[i].speed.UploadMbps = 100
					m = contract.ThroughputMeasurement{}
				}
				inputs[i].uploadSpeed = m
			}
			if d := evaluateSelector(s, inputs, contract.SelectorDecision{}, now); d.NodeID != "" || d.Candidates[0].Reason != "no_fresh_upload_measurement" {
				t.Fatal("unproven upload accepted", d)
			}
		})
	}
	s, inputs := selectionFixture(now)
	s.Policy.Mode = "highest_throughput"
	for i := range inputs {
		inputs[i].speed = contract.ThroughputMeasurement{}
		inputs[i].uploadSpeed = contract.ThroughputMeasurement{OK: true, Samples: 64, At: now.UnixMilli(), UploadMbps: 10000}
	}
	if d := evaluateSelector(s, inputs, contract.SelectorDecision{}, now); d.NodeID != "" {
		t.Fatal("upload substituted for download", d)
	}
}
func TestThroughputDirectionsPersistAndSmoothSeparately(t *testing.T) {
	c := new(nodeCounters)
	download := contract.ThroughputMeasurement{At: 1000, Target: "https://download.example", OK: true, Samples: 1, DownloadMbps: 100}
	c.recordThroughput(download)
	upload := contract.ThroughputMeasurement{Direction: "upload", At: 2000, Target: "https://upload.example", OK: true, Samples: 1, UploadMbps: 10}
	c.recordThroughput(upload)
	upload.At, upload.UploadMbps = 3000, 20
	c.recordThroughput(upload)
	if c.throughput != download || c.uploadThroughput.Samples != 2 || c.uploadThroughput.UploadMbps != 12 {
		t.Fatal(c.snapshot())
	}
	restored := new(nodeCounters)
	restored.restore(c.snapshot())
	if restored.throughput != download || restored.uploadThroughput != c.uploadThroughput || len(restored.throughputHistory) != 3 {
		t.Fatal(restored.snapshot())
	}
	upload.OK, upload.At = false, 4000
	restored.recordThroughput(upload)
	if restored.throughput != download || restored.uploadThroughput.OK {
		t.Fatal("failed upload changed download", restored.snapshot())
	}
	for i := range 32 {
		download.At = int64(5000 + i)
		restored.recordThroughput(download)
	}
	if len(restored.throughputHistory) != 16 || restored.uploadThroughput.At != 4000 {
		t.Fatal("unbounded or conflated history")
	}
}

func TestSharedUploadScheduleDeduplicatesAndHonorsNetworkPolicy(t *testing.T) {
	r := newTestRuntime(t)
	if _, err := r.Save(t.Context(), testNode(t, "a", "a")); err != nil {
		t.Fatal(err)
	}
	service := NewSelectorService(r)
	for _, name := range []string{"one", "two"} {
		if _, err := service.Save(t.Context(), contract.Selector{Name: name, NodeID: "a", Policy: &contract.SelectorPolicy{Mode: "failover", Candidates: []contract.SelectorCandidate{{NodeID: "a", Enabled: true, Weight: 1}}}}); err != nil {
			t.Fatal(err)
		}
	}
	status, err := r.Monitoring(t.Context())
	if err != nil || status.Jobs != 0 || status.Config.UploadSpeed != nil {
		t.Fatal(status, err)
	}
	config := status.Config
	config.Probe.NetworkCostPolicy = "cached_only"
	config.UploadSpeed = &contract.SpeedSchedule{Enabled: true, Test: contract.SpeedTestRequest{URL: "https://upload.example/test", AllowUpload: true}}
	status, err = r.SaveMonitoring(t.Context(), config)
	if err != nil || status.Jobs != 1 || status.Workers > 4 {
		t.Fatal("duplicate upload jobs", status, err)
	}
	status, err = r.SetMonitoringNetworkState(t.Context(), contract.MonitoringNetworkState{Online: true, Metered: true, Foreground: true})
	if err != nil || status.Jobs != 0 {
		t.Fatal("metered upload enabled implicitly", status, err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := NewNodeRuntime(r.path)
	defer reopened.Close()
	status, err = reopened.Monitoring(t.Context())
	if err != nil || status.Config.UploadSpeed == nil || status.Config.UploadSpeed.Test.Direction != "upload" || status.Jobs != 1 {
		t.Fatal("upload schedule not restored", status, err)
	}
}

func BenchmarkUploadBalancedRanking(b *testing.B) {
	for _, size := range []int{100, 1000} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			now := time.Unix(10000, 0)
			selector, pair := selectionFixture(now)
			selector.Policy.Mode, selector.Policy.UploadTarget = "balanced", "https://upload.example/test"
			selector.Policy.Weights.Upload = 1
			inputs := make([]selectionInput, size)
			for i := range inputs {
				inputs[i] = pair[i%2]
				inputs[i].config.NodeID = fmt.Sprint(i)
				inputs[i].uploadSpeed = contract.ThroughputMeasurement{Direction: "upload", At: now.UnixMilli() - 100, OK: true, Samples: 3, Target: selector.Policy.UploadTarget, UploadMbps: 30}
			}
			b.ReportAllocs()
			for b.Loop() {
				evaluateSelector(selector, inputs, contract.SelectorDecision{}, now)
			}
		})
	}
}
