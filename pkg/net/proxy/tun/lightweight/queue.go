package lightweight

// sliceQueue retains the head capacity during normal FIFO use. Empty queues
// discard unusually large backing arrays so a burst cannot pin metadata for
// the remainder of an idle connection's lifetime. Callers serialize access.
type sliceQueue[T any] struct {
	items []T
	head  int
}

func (q *sliceQueue[T]) len() int    { return len(q.items) - q.head }
func (q *sliceQueue[T]) values() []T { return q.items[q.head:] }
func (q *sliceQueue[T]) pop() {
	var zero T
	q.items[q.head] = zero
	q.head++
	if q.head == len(q.items) {
		q.head = 0
		if cap(q.items) > 64 {
			q.items = nil
		} else {
			q.items = q.items[:0]
		}
	}
}
func (q *sliceQueue[T]) push(v T) {
	if len(q.items) == cap(q.items) && q.head > 0 {
		n := copy(q.items, q.items[q.head:])
		clear(q.items[n:])
		q.items = q.items[:n]
		q.head = 0
	}
	q.items = append(q.items, v)
}
func (q *sliceQueue[T]) insert(i int, v T) {
	q.push(v)
	active := q.values()
	copy(active[i+1:], active[i:len(active)-1])
	active[i] = v
}
func (q *sliceQueue[T]) reset() { q.items = nil; q.head = 0 }
