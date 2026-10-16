package lightweight

import "time"

// Connection lock -> output waiter lock -> scheduler lock. The writer never
// takes a connection lock. FIFO admission waits for an actual capacity-release
// event; no timer polls a full device queue. At most one waiter per connection.
func (c *TCPConn) waitOutput(bytes int) {
	s := c.stack
	c.outputWaiting = true
	s.outputMu.Lock()
	if len(s.outgoing) < cap(s.outgoing) && s.memory.Load()+int64(bytes) <= s.config.MemoryLimit {
		c.outputReady.Store(true)
	} else if c.outputEntry == nil {
		c.outputEntry = s.outputWaiters.PushBack(c)
	}
	s.outputMu.Unlock()
}
func (s *Stack) wakeOutput() {
	s.outputMu.Lock()
	entry := s.outputWaiters.Front()
	if entry != nil {
		c := entry.Value.(*TCPConn)
		s.outputWaiters.Remove(entry)
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
		c.outputEntry = nil
	}
	s.outputMu.Unlock()
}
