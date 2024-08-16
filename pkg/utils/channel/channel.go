package channel

import (
	"sync"
	"sync/atomic"
)

type Channel[T any] struct {
	mu    *sync.Mutex
	rcond *sync.Cond
	wcond *sync.Cond
	buf   []T

	max    int
	size   int
	i      int
	tail   int
	closed atomic.Bool
}

func NewChannel[T any](size int) *Channel[T] {
	mu := &sync.Mutex{}
	return &Channel[T]{
		mu:    mu,
		rcond: sync.NewCond(mu),
		wcond: sync.NewCond(mu),
		buf:   make([]T, size),
		max:   size,
	}
}

func (c *Channel[T]) Push(s T) {
	if c.closed.Load() {
		return
	}

	c.mu.Lock()

	for c.size == c.max && !c.closed.Load() {
		c.wcond.Wait()
	}

	if c.closed.Load() {
		c.mu.Unlock()
		return
	}

	c.buf[c.tail] = s
	c.size++
	c.tail++
	if c.tail == c.max {
		c.tail = 0
	}

	c.mu.Unlock()
	c.rcond.Broadcast()
}

func (c *Channel[T]) Pop(max int, f func([]T)) bool {
	if c.closed.Load() && c.size == 0 {
		return false
	}

	if max <= 0 {
		return true
	}

	if max > c.max {
		max = c.max
	}

	c.mu.Lock()

	for c.size == 0 && !c.closed.Load() {
		c.rcond.Wait()
	}

	if c.size == 0 && c.closed.Load() {
		c.mu.Unlock()
		return false
	}

	end := min(c.max, c.i+min(max, c.size))

	f(c.buf[c.i:end])
	c.size -= end - c.i
	c.i = end
	if c.i >= c.max {
		c.i = 0
	}

	c.mu.Unlock()
	c.wcond.Broadcast()
	return true
}

func (c *Channel[T]) Close() {
	if c.closed.Load() {
		return
	}

	c.closed.Store(true)

	c.wcond.Broadcast()
	c.rcond.Broadcast()
}
