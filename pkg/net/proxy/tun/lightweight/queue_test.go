package lightweight

import (
	"slices"
	"testing"
)

func TestQueueCompactionAndOwnership(t *testing.T) {
	var q sliceQueue[*int]
	for i := range 64 {
		q.push(new(i))
	}
	old := q.items
	for range 32 {
		q.pop()
	}
	for i := range 32 {
		if old[i] != nil {
			t.Fatal("popped queue entry retained its owner")
		}
	}
	q.insert(7, new(99)) // Compacts the occupied head before inserting.
	if q.len() != 33 || *q.values()[7] != 99 || *q.values()[8] != 39 {
		t.Fatal("insert lost FIFO order")
	}
	for q.len() > 0 {
		q.pop()
	}
	if q.head != 0 || len(q.items) != 0 || cap(q.items) != 64 {
		t.Fatal("ordinary FIFO capacity was lost")
	}
	for i := range 1000 {
		q.push(new(i))
	}
	for q.len() > 0 {
		q.pop()
	}
	if cap(q.items) > 64 {
		t.Fatal("empty queue retained a burst-sized allocation")
	}
}

func TestQueueReclaimsPartiallyDrainedBurst(t *testing.T) {
	var q sliceQueue[int]
	for i := range 4096 {
		q.push(i)
	}
	for want := range 4095 {
		if q.values()[0] != want {
			t.Fatal("queue shrink reordered entries")
		}
		q.pop()
		if cap(q.items) > max(64, 2*q.len()) {
			t.Fatalf("%d remaining entries retained capacity %d", q.len(), cap(q.items))
		}
	}
	if q.values()[0] != 4095 {
		t.Fatal("queue shrink lost its last entry")
	}
	q.push(4096)
	q.insert(1, -1)
	if q.values()[1] != -1 || q.values()[2] != 4096 {
		t.Fatal("queue failed after shrinking and inserting")
	}
}

func TestQueueInsertAtEveryPosition(t *testing.T) {
	for pos := range 11 {
		var q sliceQueue[int]
		for i := range 10 {
			q.push(i)
		}
		q.insert(pos, 99)
		want := slices.Insert([]int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, pos, 99)
		if !slices.Equal(q.values(), want) {
			t.Fatalf("position %d: %v", pos, q.values())
		}
	}
}
