package node

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestProbeSchedulerHardBoundCancellationAndIdle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newProbeScheduler()
		defer s.close()
		synctest.Wait()
		if got := s.status(); got.Jobs != 0 || got.Workers != 0 || got.Completed != 0 {
			t.Fatal(got)
		}
		var running, peak, canceled atomic.Int32
		jobs := make([]probeJob, 1000)
		for i := range jobs {
			jobs[i] = probeJob{key: fmt.Sprint(i), interval: time.Minute, timeout: time.Hour, concurrency: 500, run: func(ctx context.Context) error {
				n := running.Add(1)
				for old := peak.Load(); n > old; old = peak.Load() {
					if peak.CompareAndSwap(old, n) {
						break
					}
				}
				<-ctx.Done()
				running.Add(-1)
				canceled.Add(1)
				return ctx.Err()
			}}
		}
		s.replace(jobs, 500)
		time.Sleep(6 * time.Second)
		synctest.Wait()
		if peak.Load() != 16 || s.status().Running != 16 {
			t.Fatal(peak.Load(), s.status())
		}
		s.replace(nil, 4)
		synctest.Wait()
		if running.Load() != 0 || canceled.Load() != 16 || s.status().Jobs != 0 {
			t.Fatal(running.Load(), canceled.Load(), s.status())
		}
		before := s.status().Completed
		time.Sleep(time.Hour)
		synctest.Wait()
		if s.status().Completed != before {
			t.Fatal("idle scheduler executed work")
		}
	})
}
func TestProbeSchedulerDeduplicatesAndCancelsChangedJob(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newProbeScheduler()
		defer s.close()
		var calls, canceled atomic.Int32
		job := probeJob{key: "shared", signature: "v1", interval: time.Minute, timeout: time.Hour, concurrency: 2, run: func(ctx context.Context) error { calls.Add(1); <-ctx.Done(); canceled.Add(1); return ctx.Err() }}
		s.replace([]probeJob{job, job}, 2)
		time.Sleep(6 * time.Second)
		synctest.Wait()
		if calls.Load() != 1 || s.status().Jobs != 1 {
			t.Fatal(calls.Load(), s.status())
		}
		s.replace([]probeJob{job}, 2)
		synctest.Wait()
		if canceled.Load() != 0 {
			t.Fatal("unchanged job canceled")
		}
		job.signature = "v2"
		job.run = func(context.Context) error { calls.Add(1); return nil }
		s.replace([]probeJob{job}, 2)
		synctest.Wait()
		if canceled.Load() != 1 {
			t.Fatal("old version still running")
		}
		time.Sleep(6 * time.Second)
		synctest.Wait()
		if calls.Load() != 2 {
			t.Fatal(calls.Load())
		}
	})
}
func TestProbeSchedulerTimeoutAndPerJobConcurrency(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newProbeScheduler()
		defer s.close()
		var running, peak atomic.Int32
		var jobs []probeJob
		for i := range 10 {
			jobs = append(jobs, probeJob{key: fmt.Sprint(i), interval: time.Minute, timeout: time.Second, concurrency: 1, run: func(ctx context.Context) error {
				n := running.Add(1)
				peak.Store(max(peak.Load(), n))
				<-ctx.Done()
				running.Add(-1)
				return ctx.Err()
			}})
		}
		s.replace(jobs, 4)
		time.Sleep(20 * time.Second)
		synctest.Wait()
		if peak.Load() != 1 || s.status().Completed != 10 || s.status().Failed != 10 {
			t.Fatal(peak.Load(), s.status())
		}
	})
}

func TestProbeSchedulerIndependentTrafficClassLimits(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newProbeScheduler()
		defer s.close()
		var health, speed atomic.Int32
		var jobs []probeJob
		for i := range 3 {
			jobs = append(jobs, probeJob{group: "health", key: fmt.Sprint(i), interval: time.Minute, timeout: time.Hour, concurrency: 3, run: func(ctx context.Context) error { health.Add(1); <-ctx.Done(); return ctx.Err() }})
		}
		jobs = append(jobs, probeJob{group: "speed", key: "speed", interval: time.Minute, timeout: time.Hour, concurrency: 1, run: func(ctx context.Context) error { speed.Add(1); <-ctx.Done(); return ctx.Err() }})
		s.replace(jobs, 4)
		time.Sleep(6 * time.Second)
		synctest.Wait()
		if health.Load() != 3 || speed.Load() != 1 || s.status().Running != 4 {
			t.Fatal(health.Load(), speed.Load(), s.status())
		}
	})
}
func TestProbeSchedulerFailureCooldown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newProbeScheduler()
		defer s.close()
		var calls atomic.Int32
		job := probeJob{key: "cooldown", interval: 5 * time.Second, timeout: time.Second, concurrency: 1, failureThreshold: 3, cooldown: 30 * time.Second, run: func(context.Context) error { calls.Add(1); return context.DeadlineExceeded }}
		s.replace([]probeJob{job}, 1)
		time.Sleep(25 * time.Second)
		synctest.Wait()
		if calls.Load() != 3 {
			t.Fatal(calls.Load())
		}
		time.Sleep(10 * time.Second)
		synctest.Wait()
		if calls.Load() != 3 {
			t.Fatal("cooldown ignored", calls.Load())
		}
		time.Sleep(11 * time.Second)
		synctest.Wait()
		if calls.Load() != 4 {
			t.Fatal(calls.Load())
		}
	})
}

func BenchmarkProbeSchedulerReplace(b *testing.B) {
	for _, size := range []int{100, 1000} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			s := newProbeScheduler()
			defer s.close()
			jobs := make([]probeJob, size)
			for i := range jobs {
				jobs[i] = probeJob{key: fmt.Sprint(i), interval: time.Hour, timeout: time.Second, concurrency: 4, run: func(context.Context) error { return nil }}
			}
			s.replace(jobs, 4)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				s.replace(jobs, 4)
			}
			b.ReportMetric(float64(s.status().Workers+1), "owned-goroutines")
		})
	}
}
