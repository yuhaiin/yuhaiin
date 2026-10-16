package lightweight

import "testing"

func TestOutputCapacityAndFIFO(t *testing.T) {
	s := &Stack{config: Config{MemoryLimit: 1 << 20}, done: make(chan struct{}), outgoing: make(chan *ownedBuffer, 1)}
	s.scheduler = newScheduler(s.done)
	s.buffers.init(s)
	first := &TCPConn{stack: s, job: timerJob{index: -1}}
	second := &TCPConn{stack: s, job: timerJob{index: -1}}
	s.outgoing <- nil
	first.waitOutput(1500)
	second.waitOutput(1500)
	for range 100 {
		s.wakeOutput()
	}
	if first.outputReady.Load() || second.outputReady.Load() || len(s.scheduler.jobs) != 0 {
		t.Fatal("full output queue repeatedly woke blocked flows")
	}
	<-s.outgoing
	// A free device slot is insufficient if no packet can fit the memory budget.
	s.memory.Store(s.config.MemoryLimit)
	s.wakeOutput()
	if first.outputReady.Load() {
		t.Fatal("insufficient memory woke blocked flow")
	}
	s.memory.Store(0)
	s.wakeOutput()
	if !first.outputReady.Load() || second.outputReady.Load() {
		t.Fatal("capacity wakeup violated FIFO order")
	}
	second.cancelOutputWait()
	if s.outputWaiters.Len() != 0 {
		t.Fatal("canceled waiter remained queued")
	}
}
