package lightweight

import "time"

// Connection lock -> output waiter lock -> scheduler lock. The writer never
// takes a connection lock. FIFO admission waits for an actual capacity-release
// event; no timer polls a full device queue. At most one waiter per connection.
func (c *TCPConn) waitOutput(bytes int) {
	s := c.stack
	c.outputWaiting = true
	s.outputMu.Lock()
	c.outputBytes = bytes
	// Register before observing capacity. A concurrent release must either see
	// this waiter or be observed by the capacity check under the same lock.
	if c.outputEntry == nil {
		c.outputEntry = s.outputWaiters.PushBack(c)
		s.outputCount.Add(1)
	}
	if s.outputWaiters.Front() == c.outputEntry && len(s.outgoing) < cap(s.outgoing) && s.buffers.canGet(bytes) {
		s.outputWaiters.Remove(c.outputEntry)
		s.outputCount.Add(-1)
		c.outputEntry = nil
		c.outputReady.Store(true)
	}
	s.outputMu.Unlock()
}
func (s *Stack) wakeOutput() {
	if s.outputCount.Load() == 0 || len(s.outgoing) >= cap(s.outgoing) {
		return
	}
	s.outputMu.Lock()
	entry := s.outputWaiters.Front()
	if entry != nil {
		c := entry.Value.(*TCPConn)
		if len(s.outgoing) >= cap(s.outgoing) || !s.buffers.canGet(c.outputBytes) {
			s.outputMu.Unlock()
			return
		}
		s.outputWaiters.Remove(entry)
		s.outputCount.Add(-1)
		c.outputEntry = nil
		c.outputReady.Store(true)
		s.scheduler.set(&c.job, time.Now())
	}
	s.outputMu.Unlock()
}
func (c *TCPConn) cancelOutputWait() {
	s := c.stack
	s.outputMu.Lock()
	if c.outputEntry != nil {
		s.outputWaiters.Remove(c.outputEntry)
		s.outputCount.Add(-1)
		c.outputEntry = nil
	}
	s.outputMu.Unlock()
}
