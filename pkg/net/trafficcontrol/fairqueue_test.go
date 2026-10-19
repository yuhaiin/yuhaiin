package trafficcontrol

import (
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
	for n := 0; n < 25; n++ {
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
