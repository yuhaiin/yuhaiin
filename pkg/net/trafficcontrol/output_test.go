package trafficcontrol

import (
	"math/rand/v2"
	"runtime"
	"slices"
	"testing"
	"time"
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
		if v, ok := q.Dequeue(false); !ok || v != 1 {
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
		if v, ok := q.Dequeue(false); !ok || v != want {
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
					if packet, ok := q.Dequeue(false); ok {
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
				if _, ok := q.Dequeue(false); !ok {
					b.Fatal("pop")
				}
			}
		})
	}
}

func TestOutputBatchPreservesFairSchedulingAndOwnership(t *testing.T) {
	for _, mode := range []SchedulerMode{SchedulerFIFO, SchedulerFair} {
		t.Run(string(mode), func(t *testing.T) {
			makeQueue := func() OutputQueue[int] {
				return NewOutputQueue(OutputOptions[int]{
					Limits: FairConfig{MaxPackets: 64, MaxBytes: 1 << 20}, Mode: mode,
					Size: func(v int) int { return 64 + v*40 },
					Classify: func(v int) Classification {
						return Classification{Host: uint64(v % 3), Flow: uint64(v % 7), Weight: 1 + v%4}
					},
					Release: func(int) { t.Fatal("unexpected drop") },
				})
			}
			batch, reference := makeQueue(), makeQueue()
			for v := range 32 {
				if !batch.Enqueue(v) || !reference.Enqueue(v) {
					t.Fatal("enqueue")
				}
			}
			var dst [7]int
			remaining := 32
			for remaining > 0 {
				n := batch.DequeueBatch(dst[:], true)
				if n != min(7, remaining) {
					t.Fatalf("batch waited or lost packets: %d", n)
				}
				for _, got := range dst[:n] {
					want, ok := reference.Dequeue(false)
					if !ok || got != want {
						t.Fatalf("batch changed DRR/order: got=%d want=%d", got, want)
					}
				}
				remaining -= n
				// Sojourn timestamps differ between independent queues.
				a, b := batch.Stats(), reference.Stats()
				a.MaxSojourn, b.MaxSojourn = 0, 0
				if a != b {
					t.Fatal("batch ownership/accounting differs", a, b)
				}
			}
			if n := batch.DequeueBatch(dst[:], false); n != 0 {
				t.Fatal("empty queue", n)
			}
			if n := batch.DequeueBatch(nil, true); n != 0 {
				t.Fatal("empty destination must not wait", n)
			}
		})
	}
}

func BenchmarkOutputQueueBurst(b *testing.B) {
	for _, mode := range []SchedulerMode{SchedulerFIFO, SchedulerFair} {
		b.Run(string(mode), func(b *testing.B) {
			q := NewOutputQueue(OutputOptions[int]{Limits: FairConfig{MaxPackets: 1024, MaxBytes: 4 << 20}, Mode: mode,
				Size: func(int) int { return 1400 }, Classify: func(int) Classification { return Classification{Host: 1, Flow: 1, Weight: 1} }, Release: func(int) { b.Fatal("drop") },
			})
			var dst [16]int
			b.ReportAllocs()
			b.SetBytes(32 * 1400)
			for b.Loop() {
				for v := range 32 {
					if !q.Enqueue(v) {
						b.Fatal("push")
					}
				}
				for range 2 {
					if n := q.DequeueBatch(dst[:], false); n != len(dst) {
						b.Fatal("pop", n)
					}
				}
			}
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*32), "ns/packet")
		})
	}
}

func TestOutputQueueCloseWakesReadersAndRetainsPendingOwnership(t *testing.T) {
	for _, mode := range []SchedulerMode{SchedulerFIFO, SchedulerFair} {
		t.Run(string(mode), func(t *testing.T) {
			makeQueue := func() OutputQueue[int] {
				return NewOutputQueue(OutputOptions[int]{Limits: FairConfig{MaxPackets: 4, MaxBytes: 4096}, Mode: mode,
					Size: func(int) int { return 100 }, Classify: func(int) Classification { return Classification{Host: 1, Flow: 1, Weight: 1} }, Release: func(int) { t.Error("Close discarded caller-owned work") },
				})
			}
			for range 32 {
				q := makeQueue()
				started, finished := make(chan struct{}), make(chan int, 1)
				go func() { var dst [4]int; close(started); finished <- q.DequeueBatch(dst[:], true) }()
				<-started
				runtime.Gosched()
				q.Close()
				select {
				case n := <-finished:
					if n != 0 {
						t.Fatal("closed reader returned work", n)
					}
				case <-time.After(time.Second):
					t.Fatal("Close did not wake reader")
				}
				q.Close()
				if q.Enqueue(1) || q.HasCapacity(100) {
					t.Fatal("closed queue still accepts work")
				}
			}
			q := makeQueue()
			q.Enqueue(1)
			q.Enqueue(2)
			q.Close()
			if _, ok := q.Dequeue(false); ok {
				t.Fatal("closed queue must leave pending work to Drain")
			}
			if got := q.Drain(); !slices.Equal(got, []int{1, 2}) {
				t.Fatal("Close lost pending ownership", got)
			}
		})
	}
}

func TestOutputBatchNewHostProgress(t *testing.T) {
	q := NewOutputQueue(OutputOptions[int]{Limits: FairConfig{MaxPackets: 64, MaxBytes: 1 << 20}, Mode: SchedulerFair,
		Size: func(int) int { return 1400 }, Classify: func(v int) Classification {
			host := uint64(1)
			if v == 99 {
				host = 2
			}
			return Classification{Host: host, Flow: host, Weight: 1}
		}, Release: func(int) { t.Fatal("drop") },
	})
	for range 40 {
		if !q.Enqueue(1) {
			t.Fatal("bulk enqueue")
		}
	}
	var dst [16]int
	if n := q.DequeueBatch(dst[:], false); n != 16 {
		t.Fatal("initial batch", n)
	}
	if !q.Enqueue(99) {
		t.Fatal("new host denied")
	}
	n := q.DequeueBatch(dst[:], false)
	at := slices.Index(dst[:n], 99)
	if at < 0 || at > 1 {
		t.Fatalf("new host blocked behind bulk backlog: %v", dst[:n])
	}
}
