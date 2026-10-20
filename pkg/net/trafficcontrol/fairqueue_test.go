package trafficcontrol

import (
	"sync"
	"testing"
	"time"
)

func TestFairQueueDRRAndPerFlowOrder(t *testing.T) {
	q := NewFairQueue[int](FairConfig{MaxPackets: 64, MaxBytes: 65536, Quantum: 1000})
	now := time.Now()
	for i := range 20 {
		if !q.Push(1, 1000, i, now) {
			t.Fatal("insert bulk")
		}
	}
	for i := range 5 {
		if !q.Push(2, 1000, 100+i, now) {
			t.Fatal("insert interactive")
		}
	}
	var orderedA, orderedB []int
	firstB := -1
	for n := range 25 {
		x, ok, drops := q.Pop(now)
		if !ok || len(drops) != 0 {
			t.Fatalf("unexpected dequeue: %t drops=%v", ok, drops)
		}
		if x >= 100 {
			orderedB = append(orderedB, x)
			if firstB < 0 {
				firstB = n
			}
		} else {
			orderedA = append(orderedA, x)
		}
	}
	if firstB > 2 {
		t.Fatalf("short flow starved behind bulk backlog: first at %d", firstB)
	}
	for i, x := range orderedA {
		if x != i {
			t.Fatalf("bulk order %v", orderedA)
		}
	}
	for i, x := range orderedB {
		if x != 100+i {
			t.Fatalf("interactive order %v", orderedB)
		}
	}
	if s := q.Stats(); s.Packets != 0 || s.Bytes != 0 || s.Flows != 0 {
		t.Fatal(s)
	}
}
func TestFairQueuePacketAndByteCaps(t *testing.T) {
	q := NewFairQueue[int](FairConfig{MaxPackets: 2, MaxBytes: 1500})
	now := time.Now()
	if !q.Push(1, 700, 1, now) || q.Push(2, 900, 2, now) || !q.Push(2, 800, 3, now) || q.Push(3, 1, 4, now) {
		t.Fatalf("bad admission caps: %+v", q.Stats())
	}
	s := q.Stats()
	if s.Packets != 2 || s.Bytes != 1500 || s.Rejected != 2 {
		t.Fatal(s)
	}
	if got := q.Drain(); len(got) != 2 {
		t.Fatal(got)
	}
	if s := q.Stats(); s.Flows != 0 || s.Bytes != 0 {
		t.Fatal(s)
	}
}
func TestFairQueueSojournDropAndDrain(t *testing.T) {
	q := NewFairQueue[int](FairConfig{MaxPackets: 64, MaxBytes: 100000, Quantum: 1000, Target: 5 * time.Millisecond, Interval: 20 * time.Millisecond})
	now := time.Now()
	for i := range 30 {
		if !q.Push(1, 1000, i, now) {
			t.Fatal(i)
		}
	}
	_, ok, discards := q.Pop(now.Add(10 * time.Millisecond))
	if !ok || len(discards) != 0 {
		t.Fatal("early AQM drop", discards)
	}
	_, ok, discards = q.Pop(now.Add(50 * time.Millisecond))
	if !ok || len(discards) == 0 {
		t.Fatal("persistent congestion was not dropped")
	}
	for _, x := range discards {
		if x < 0 || x >= 30 {
			t.Fatal(x)
		}
	}
	all := q.Drain()
	if len(all)+len(discards) != 28 {
		t.Fatalf("lost ownership: drain=%d dropped=%d", len(all), len(discards))
	}
	if q.Stats().DroppedAQM == 0 {
		t.Fatal("AQM counter not incremented")
	}
}
func TestFairQueueIdleLastPacketNotDropped(t *testing.T) {
	q := NewFairQueue[int](FairConfig{MaxPackets: 8, MaxBytes: 8000, Quantum: 1500, Target: time.Millisecond, Interval: time.Millisecond})
	now := time.Now()
	q.Push(1, 500, 7, now)
	x, ok, drops := q.Pop(now.Add(time.Minute))
	if !ok || x != 7 || len(drops) != 0 {
		t.Fatal("isolated flow dropped", x, ok, drops)
	}
}

func TestFairQueueConcurrentFlowOwnership(t *testing.T) {
	type item struct{ flow, seq int }
	const flows, perFlow = 16, 64
	q := NewFairQueue[item](FairConfig{MaxPackets: flows * perFlow, MaxBytes: flows * perFlow * 512, Quantum: 1514})
	now := time.Now()
	var wg sync.WaitGroup
	for flow := range flows {
		wg.Go(func() {
			for n := range perFlow {
				if !q.Push(uint64(flow), 512, item{flow, n}, now) {
					t.Errorf("flow %d admission failed", flow)
					return
				}
			}
		})
	}
	wg.Wait()
	var seen [flows]int
	for range flows * perFlow {
		x, ok, drops := q.Pop(now)
		if !ok || len(drops) != 0 {
			t.Fatal("missing packet or premature drop")
		}
		if x.seq != seen[x.flow] {
			t.Fatalf("flow=%d out of order: got=%d expected=%d", x.flow, x.seq, seen[x.flow])
		}
		seen[x.flow]++
	}
	for i := range flows {
		if seen[i] != perFlow {
			t.Fatalf("flow %d lost packets", i)
		}
	}
	if s := q.Stats(); s.Packets != 0 || s.Bytes != 0 || s.Flows != 0 {
		t.Fatal(s)
	}
}

func TestWeightedDRRDoesNotStarveBulk(t *testing.T) {
	q := NewFairQueue[int](FairConfig{MaxPackets: 256, MaxBytes: 256000, Quantum: 1000})
	now := time.Now()
	for i := range 80 {
		if !q.PushWeighted(1, 1000, i, now, 4) {
			t.Fatal("control flow admission")
		}
		if !q.PushWeighted(2, 1000, 100+i, now, 1) {
			t.Fatal("bulk flow admission")
		}
	}
	control, bulk := 0, 0
	for range 40 {
		n, ok, drops := q.Pop(now)
		if !ok || len(drops) != 0 {
			t.Fatal("scheduler dropped unexpectedly", drops)
		}
		if n < 100 {
			control++
		} else {
			bulk++
		}
	}
	if bulk == 0 || control <= bulk {
		t.Fatalf("weight ratio did not preserve non-starving priority: control=%d bulk=%d", control, bulk)
	}
	remaining := q.Drain()
	if len(remaining) != 120 {
		t.Fatalf("packet ownership changed: %d", len(remaining))
	}
}

func TestFairQueueAQMDeadlineAtMonotonicEpoch(t *testing.T) {
	q := NewFairQueue[int](FairConfig{MaxPackets: 16, MaxBytes: 1 << 20, Quantum: 100, Target: time.Millisecond, Interval: 100 * time.Millisecond})
	for i := range 8 {
		if !q.Push(1, 100, i, queueEpoch.Add(-200*time.Millisecond)) {
			t.Fatal("push")
		}
	}
	if _, ok, drops := q.Pop(queueEpoch.Add(-100 * time.Millisecond)); !ok || len(drops) != 0 {
		t.Fatal("first congestion sample", ok, drops)
	}
	if _, ok, drops := q.Pop(queueEpoch.Add(time.Millisecond)); !ok || len(drops) == 0 {
		t.Fatal("zero-offset AQM deadline was mistaken for an unset timer", ok, drops)
	}
}

func TestFairQueueAQMZeroTimestamp(t *testing.T) {
	q := NewFairQueue[int](FairConfig{MaxPackets: 16, MaxBytes: 1 << 20, Quantum: 100, Target: time.Millisecond, Interval: 50 * time.Millisecond})
	for i := range 8 {
		if !q.Push(1, 100, i, time.Time{}) {
			t.Fatal("push")
		}
	}
	q.Pop(queueEpoch.Add(100 * time.Millisecond))
	if _, ok, drops := q.Pop(queueEpoch.Add(200 * time.Millisecond)); !ok || len(drops) == 0 {
		t.Fatal("old timestamp overflow suppressed AQM", ok, drops)
	}
}
