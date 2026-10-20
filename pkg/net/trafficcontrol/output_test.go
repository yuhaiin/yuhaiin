package trafficcontrol

import (
	"math/rand/v2"
	"testing"
)

func TestOutputQueueDefersClassificationUntilContention(t *testing.T) {
	classified := 0
	q := NewOutputQueue(OutputOptions[int]{Limits: FairConfig{MaxPackets: 4, MaxBytes: 4096}, Mode: SchedulerFair,
		Size: func(int) int { return 100 }, Classify: func(v int) Classification { classified++; return Classification{Host: 1, Flow: 1, Weight: 1} }, Release: func(int) { t.Fatal("unexpected drop") },
	})
	for range 100 {
		if !q.Enqueue(1) {
			t.Fatal("enqueue")
		}
		if v, ok := q.Dequeue(nil, false); !ok || v != 1 {
			t.Fatal("dequeue")
		}
	}
	if classified != 0 {
		t.Fatal("sparse packets entered scheduler", classified)
	}
	q.Enqueue(1)
	q.Enqueue(2)
	if classified != 2 {
		t.Fatal("contended packets were not classified", classified)
	}
	for _, want := range []int{1, 2} {
		if v, ok := q.Dequeue(nil, false); !ok || v != want {
			t.Fatal("promotion changed flow order", v, want)
		}
	}
}

func TestOutputQueueOwnershipAndBounds(t *testing.T) {
	for _, mode := range []SchedulerMode{SchedulerFIFO, SchedulerFair} {
		t.Run(string(mode), func(t *testing.T) {
			owned := make(map[int]bool)
			var q OutputQueue[int]
			release := func(v int) {
				if !owned[v] {
					t.Fatalf("duplicate or unowned release: %d", v)
				}
				delete(owned, v)
				_ = q.Stats() // A release callback must run outside the ownership lock.
			}
			q = NewOutputQueue(OutputOptions[int]{Limits: FairConfig{MaxPackets: 16, MaxBytes: 4000}, Mode: mode,
				Size: func(v int) int { return v%1400 + 1 }, Classify: func(v int) Classification {
					return Classification{Host: uint64(v % 4), Flow: uint64(v % 32), Weight: 1}
				}, Release: release,
			})
			random := rand.New(rand.NewPCG(1, 2))
			for v := range 3000 {
				if random.IntN(3) == 0 {
					if packet, ok := q.Dequeue(nil, false); ok {
						release(packet)
					}
				} else if q.Enqueue(v) {
					owned[v] = true
				}
				if s := q.Stats(); s.Packets > 16 || s.Bytes > 4000 || s.Bytes < 0 {
					t.Fatal("queue exceeded budget", s)
				}
			}
			for _, v := range q.Drain() {
				release(v)
			}
			if len(owned) != 0 || q.Stats().Packets != 0 || q.Stats().Bytes != 0 {
				t.Fatal("shutdown lost ownership", owned, q.Stats())
			}
		})
	}
}

func BenchmarkOutputQueueSparse(b *testing.B) {
	for _, mode := range []SchedulerMode{SchedulerFIFO, SchedulerFair} {
		b.Run(string(mode), func(b *testing.B) {
			q := NewOutputQueue(OutputOptions[int]{Limits: FairConfig{MaxPackets: 1024, MaxBytes: 4 << 20}, Mode: mode,
				Size: func(int) int { return 1400 }, Classify: func(int) Classification { return Classification{Host: 1, Flow: 1, Weight: 1} }, Release: func(int) { b.Fatal("drop") },
			})
			b.ReportAllocs()
			for b.Loop() {
				if !q.Enqueue(1) {
					b.Fatal("push")
				}
				if _, ok := q.Dequeue(nil, false); !ok {
					b.Fatal("pop")
				}
			}
		})
	}
}
