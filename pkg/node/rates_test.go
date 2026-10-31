package node

import (
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
)

func TestPassiveRateWindowUsesObservedCoverageAndExpires(t *testing.T) {
	n := new(nodeCounters)
	now := time.Unix(10000, 0)
	previous := [2]uint64{}
	for i := range 12 {
		end := now.Add(time.Duration(i+1) * 5 * time.Second)
		current := nodeTotals{UploadBytes: uint64(i+1) * 5000, DownloadBytes: uint64(i+1) * 10000}
		n.sampleTraffic(end.Add(-5*time.Second), end, previous, current)
		previous = [2]uint64{current.UploadBytes, current.DownloadBytes}
		value := n.freshTrafficWindow(end.UnixMilli())
		if value == nil || value.WindowMS != int64(i+1)*5000 || value.UploadBps != "1000" || value.DownloadBps != "2000" {
			t.Fatal(value)
		}
	}
	end := now.Add(65 * time.Second)
	n.sampleTraffic(end.Add(-5*time.Second), end, previous, nodeTotals{UploadBytes: previous[0], DownloadBytes: previous[1]})
	value := n.freshTrafficWindow(end.UnixMilli())
	if value == nil || value.WindowMS != 60000 || value.UploadBps != "916" || value.DownloadBps != "1833" {
		t.Fatal("idle interval omitted from mean", value)
	}
	if n.freshTrafficWindow(end.Add(11*time.Second).UnixMilli()) != nil || n.freshTrafficWindow(end.Add(-time.Second).UnixMilli()) != nil {
		t.Fatal("stale/future window accepted")
	}
	value.UploadBps = "changed"
	if n.freshTrafficWindow(end.UnixMilli()).UploadBps == "changed" {
		t.Fatal("mutable window escaped")
	}
	if new(nodeCounters).freshTrafficWindow(end.UnixMilli()) != nil {
		t.Fatal("fresh counters invented a rate")
	}
}
func TestPassiveRateWindowJitterSleepAndCounterReset(t *testing.T) {
	start := time.Unix(10000, 0)
	n := new(nodeCounters)
	n.sampleTraffic(start, start.Add(3*time.Second), [2]uint64{}, nodeTotals{UploadBytes: 3000})
	n.sampleTraffic(start.Add(3*time.Second), start.Add(10*time.Second), [2]uint64{3000, 0}, nodeTotals{UploadBytes: 17000})
	value := n.freshTrafficWindow(start.Add(10 * time.Second).UnixMilli())
	if value == nil || value.WindowMS != 10000 || value.UploadBps != "1700" {
		t.Fatal("unweighted jittered samples", value)
	}
	for _, tc := range []struct {
		name       string
		start, end time.Time
		previous   [2]uint64
		current    nodeTotals
	}{
		{name: "sleep", start: start.Add(10 * time.Second), end: start.Add(2 * time.Minute), previous: [2]uint64{17000, 0}, current: nodeTotals{UploadBytes: 20000}},
		{name: "clock_backwards", start: start.Add(time.Minute), end: start, previous: [2]uint64{}, current: nodeTotals{}},
		{name: "counter_reset", start: start, end: start.Add(5 * time.Second), previous: [2]uint64{10, 0}, current: nodeTotals{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n.sampleTraffic(tc.start, tc.end, tc.previous, tc.current)
			if n.window.Load() != nil {
				t.Fatal("unreliable interval published")
			}
			end := tc.end.Add(5 * time.Second)
			n.sampleTraffic(tc.end, end, [2]uint64{}, nodeTotals{UploadBytes: 500})
			if value := n.freshTrafficWindow(end.UnixMilli()); value == nil || value.WindowMS != 5000 || value.UploadBps != "100" {
				t.Fatal("gap retained old buckets", value)
			}
		})
	}
}
func TestRecentTCPDialRatioExcludesOtherEvidenceAndOldSamples(t *testing.T) {
	now := time.Unix(10000, 0).UnixMilli()
	samples := []contract.HealthSample{
		{Kind: "connect", At: now - 100, OK: true}, {Kind: "connect", At: now - 200, OK: false},
		{Kind: "response", At: now, OK: true}, {Kind: "io", At: now, OK: false}, {Kind: "session", At: now, OK: false},
		{Kind: "https", At: now, OK: false}, {Kind: "connect", At: now + 1, OK: false}, {Kind: "connect", At: now - 120001, OK: false},
	}
	value := recentTCPDials(contract.ChannelHealth{Samples: samples}, now)
	if value == nil || value.Samples != 2 || value.Failures != 1 || value.FailureRate != .5 || value.WindowMS != 120000 || value.SampleLimit != 64 {
		t.Fatal(value)
	}
	if recentTCPDials(contract.ChannelHealth{}, now) != nil {
		t.Fatal("unknown errors displayed as zero")
	}
}
func TestPassiveRateUpdatesDoNotCauseIdleSQLiteWrites(t *testing.T) {
	r := newTestRuntime(t)
	if _, err := r.Save(t.Context(), testNode(t, "a", "a")); err != nil {
		t.Fatal(err)
	}
	if err := r.observer.flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	changes := func() int {
		var count int
		if err := r.sqlite.DB().QueryRowContext(t.Context(), "SELECT total_changes()").Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	before := changes()
	for range 3 {
		r.observer.mu.Lock()
		r.observer.lastSample = time.Now().Add(-5 * time.Second)
		r.observer.mu.Unlock()
		if err := r.observer.flush(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if got := changes(); got != before {
		t.Fatal("idle rate sampling wrote SQLite", before, got)
	}
	if r.observer.counter("a").status("a").TrafficWindow == nil {
		t.Fatal("existing observer did not publish mean")
	}
}
func TestPassiveRateConcurrentStatusReads(t *testing.T) {
	n := new(nodeCounters)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 1000 {
				_ = n.freshTrafficWindow(time.Now().UnixMilli())
			}
		})
	}
	start := time.Now().Add(-5 * time.Second)
	for i := range 1000 {
		n.sampleTraffic(start, start.Add(5*time.Second), [2]uint64{}, nodeTotals{UploadBytes: uint64(i)})
	}
	wg.Wait()
}
func BenchmarkPassiveRateSampling(b *testing.B) {
	for _, count := range []int{100, 1000} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			counters := make([]nodeCounters, count)
			start := time.Unix(10000, 0)
			b.ReportAllocs()
			for b.Loop() {
				start = start.Add(5 * time.Second)
				for i := range counters {
					counters[i].sampleTraffic(start, start.Add(5*time.Second), [2]uint64{}, nodeTotals{UploadBytes: 5000, DownloadBytes: 10000})
				}
			}
			b.ReportMetric(float64(reflect.TypeFor[nodeTrafficWindow]().Size()), "bytes/window-ring")
		})
	}
}

func TestPassiveRateMonotonicSuspendAndWallClockDrift(t *testing.T) {
	for _, value := range []struct {
		elapsed, wall time.Duration
		want          bool
	}{
		{5 * time.Second, 5 * time.Second, true}, {5 * time.Second, 2 * time.Hour, false},
		{5 * time.Second, -time.Second, false}, {5 * time.Second, 7 * time.Second, false},
		{0, 5 * time.Second, false}, {11 * time.Second, 11 * time.Second, false},
	} {
		if got := reliableTrafficSpan(value.elapsed, value.wall); got != value.want {
			t.Fatal(value, got)
		}
	}
}

func TestRecentTCPDialSummaryHardBound(t *testing.T) {
	now := time.Unix(10000, 0).UnixMilli()
	samples := make([]contract.HealthSample, 1000)
	for i := range samples {
		samples[i] = contract.HealthSample{Kind: "connect", At: now, OK: true}
	}
	value := recentTCPDials(contract.ChannelHealth{Samples: samples}, now)
	if value == nil || value.Samples != 64 || value.FailureRate != 0 {
		t.Fatal(value)
	}
}

func TestPassiveRateRestartUsesPersistedBaseline(t *testing.T) {
	r := newTestRuntime(t)
	if _, err := r.Save(t.Context(), testNode(t, "a", "a")); err != nil {
		t.Fatal(err)
	}
	r.observer.counter("a").upload.Add(1 << 20)
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := NewNodeRuntime(r.path)
	defer reopened.Close()
	values, err := reopened.Statuses(t.Context(), []string{"a"})
	if err != nil || len(values) != 1 || values[0].TrafficWindow != nil || values[0].UploadBytes != "1048576" {
		t.Fatal("restart restored a live rate window", values, err)
	}
	reopened.observer.mu.Lock()
	reopened.observer.lastSample = time.Now().Add(-5 * time.Second)
	reopened.observer.mu.Unlock()
	if err := reopened.observer.flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	value := reopened.observer.counter("a").status("a").TrafficWindow
	if value == nil || value.UploadBps != "0" {
		t.Fatal("historical bytes became new traffic", value)
	}
}

func TestPassiveRatePartialBucketIsClippedToMinute(t *testing.T) {
	n := new(nodeCounters)
	start := time.Unix(10000, 0)
	previous := [2]uint64{}
	for i := range 7 {
		end := start.Add(time.Duration(i+1) * 9 * time.Second)
		current := nodeTotals{UploadBytes: 9000}
		n.sampleTraffic(end.Add(-9*time.Second), end, previous, current)
		previous = [2]uint64{current.UploadBytes, 0}
	}
	value := n.freshTrafficWindow(start.Add(63 * time.Second).UnixMilli())
	if value == nil || value.WindowMS != 60000 || value.UploadBps != "100" {
		t.Fatal("old bucket was not clipped proportionally", value)
	}
}
