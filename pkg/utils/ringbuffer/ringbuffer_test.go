package ringbuffer

import "testing"

func TestCapacityIsExactAndRespectsChanges(t *testing.T) {
	for _, maximum := range []int{0, 1, 7, 8, 9, 100, 200, 5000} {
		limit := maximum
		q := NewRingBuffer[int](8, func() int { return limit })
		for i := range maximum {
			if !q.Push(i) {
				t.Fatalf("limit=%d rejected %d", maximum, i)
			}
		}
		if q.Push(-1) {
			t.Fatalf("limit=%d accepted extra entry", maximum)
		}
		limit = maximum / 2
		if q.Push(-1) {
			t.Fatalf("shrunk limit=%d accepted extra entry", limit)
		}
		for i := range maximum {
			v, ok := q.Pop()
			if !ok || v != i {
				t.Fatalf("FIFO: got %d,%t want %d", v, ok, i)
			}
		}
		limit = maximum + 3
		for i := range limit {
			if !q.Push(i) {
				t.Fatalf("increased limit=%d rejected %d", limit, i)
			}
		}
		if q.Push(-1) {
			t.Fatalf("increased limit=%d accepted extra entry", limit)
		}
	}
}

func TestGrowthPreservesWrappedOrder(t *testing.T) {
	q := NewRingBuffer[int](3, func() int { return 7 })
	for i := range 3 {
		q.Push(i)
	}
	q.Pop()
	q.Pop()
	for i := 3; i < 9; i++ {
		if !q.Push(i) {
			t.Fatalf("rejected %d", i)
		}
	}
	if q.Push(9) {
		t.Fatal("exceeded seven entries")
	}
	for want := 2; want < 9; want++ {
		if got, ok := q.Pop(); !ok || got != want {
			t.Fatalf("got %d,%t want %d", got, ok, want)
		}
	}
}
