package lightweight

import "time"

// Connection lock -> output waiter lock -> scheduler lock. The writer never
// takes a connection lock. FIFO admission waits for an actual capacity-release
// event; no timer polls a full device queue. At most one waiter per connection.
func (s *Stack) outputHasCapacity(bytes int) bool { return s.output.HasCapacity(bytes) }

func (c *TCPConn) waitOutput(bytes int) {
	s := c.stack
	c.outputWaiting = true
	s.outputMu.Lock()
	c.outputBytes = bytes
	// Register before observing capacity. A concurrent release must either see
	// this waiter or be observed by the capacity check under the same lock.
	if !c.outputQueued {
		s.outputWaiters.push(c)
		s.outputCount.Add(1)
	}
	if s.outputWaiters.head == c && s.outputHasCapacity(bytes) && s.buffers.canGet(bytes) {
		s.outputWaiters.remove(c)
		s.outputCount.Add(-1)
		c.outputReady.Store(true)
	}
	s.outputMu.Unlock()
}
func (s *Stack) wakeOutput() {
	if s.outputCount.Load() == 0 || !s.outputHasCapacity(0) {
		return
	}
	s.outputMu.Lock()
	c := s.outputWaiters.head
	if c != nil {
		if !s.outputHasCapacity(c.outputBytes) || !s.buffers.canGet(c.outputBytes) {
			s.outputMu.Unlock()
			return
		}
		s.outputWaiters.remove(c)
		s.outputCount.Add(-1)
		c.outputReady.Store(true)
		s.scheduler.set(&c.job, time.Now())
	}
	s.outputMu.Unlock()
}
func (c *TCPConn) cancelOutputWait() {
	s := c.stack
	s.outputMu.Lock()
	if c.outputQueued {
		s.outputWaiters.remove(c)
		s.outputCount.Add(-1)
	}
	s.outputMu.Unlock()
}

// Waiters embed their links; a full output queue must not allocate a list node
// on every retry. All queue access holds outputMu, including cancellation.
type outputQueue struct {
	head, tail *TCPConn
	n          int
}

func (q *outputQueue) Len() int { return q.n }
func (q *outputQueue) push(c *TCPConn) {
	c.outputPrev = q.tail
	c.outputNext = nil
	c.outputQueued = true
	if q.tail == nil {
		q.head = c
	} else {
		q.tail.outputNext = c
	}
	q.tail = c
	q.n++
}
func (q *outputQueue) remove(c *TCPConn) {
	if c.outputPrev == nil {
		q.head = c.outputNext
	} else {
		c.outputPrev.outputNext = c.outputNext
	}
	if c.outputNext == nil {
		q.tail = c.outputPrev
	} else {
		c.outputNext.outputPrev = c.outputPrev
	}
	c.outputPrev, c.outputNext = nil, nil
	c.outputQueued = false
	q.n--
}
