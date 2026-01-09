// copy from https://github.com/quic-go/quic-go
package ringbuffer

import "sync"

// A RingBuffer is a ring buffer.
// It acts as a heap that doesn't cause any allocations.
type RingBuffer[T any] struct {

	// maxCap is the maximum capacity of the ring buffer.
	maxCap func() int

	ring             []T
	headPos, tailPos int

	mu   sync.Mutex
	full bool
}

// NewRingBuffer returns a new ring buffer.
func NewRingBuffer[T any](initCap int, maxCap func() int) *RingBuffer[T] {
	if initCap <= 0 {
		initCap = 8
	}

	return &RingBuffer[T]{
		maxCap: maxCap,
		ring:   make([]T, initCap),
	}
}

// Len returns the number of elements in the ring buffer.
func (r *RingBuffer[T]) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.full {
		return len(r.ring)
	}
	if r.tailPos >= r.headPos {
		return r.tailPos - r.headPos
	}
	return r.tailPos - r.headPos + len(r.ring)
}

// Empty says if the ring buffer is empty.
func (r *RingBuffer[T]) empty() bool {
	return !r.full && r.headPos == r.tailPos
}

// Push adds a new element.
// If the ring buffer is full, its capacity is increased first.
func (r *RingBuffer[T]) Push(t T) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.full {
		if len(r.ring) >= r.maxCap() {
			return false
		}
		r.grow()
	}

	r.ring[r.tailPos] = t
	r.tailPos++
	if r.tailPos == len(r.ring) {
		r.tailPos = 0
	}
	if r.tailPos == r.headPos {
		r.full = true
	}

	return true
}

// Pop returns the next element.
// It must not be called when the buffer is empty, that means that
// callers might need to check if there are elements in the buffer first.
func (r *RingBuffer[T]) Pop() (T, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.empty() {
		return *new(T), false
	}

	r.full = false
	t := r.ring[r.headPos]
	r.ring[r.headPos] = *new(T)
	r.headPos++
	if r.headPos == len(r.ring) {
		r.headPos = 0
	}
	return t, true
}

// Peek returns the next element.
// It must not be called when the buffer is empty, that means that
// callers might need to check if there are elements in the buffer first.
func (r *RingBuffer[T]) Peek() (T, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.empty() {
		return *new(T), false
	}
	return r.ring[r.headPos], true
}

// Grow the maximum size of the queue.
// This method assume the queue is full.
func (r *RingBuffer[T]) grow() {
	oldRing := r.ring
	newSize := len(oldRing) * 2
	if newSize == 0 {
		newSize = 1
	}
	r.ring = make([]T, newSize)
	headLen := copy(r.ring, oldRing[r.headPos:])
	copy(r.ring[headLen:], oldRing[:r.headPos])
	r.headPos, r.tailPos, r.full = 0, len(oldRing), false
}

// Clear removes all elements.
func (r *RingBuffer[T]) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()

	var zeroValue T
	for i := range r.ring {
		r.ring[i] = zeroValue
	}
	r.headPos, r.tailPos, r.full = 0, 0, false
}
