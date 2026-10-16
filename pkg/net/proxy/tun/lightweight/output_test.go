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

func TestOutputCancellationKeepsFIFO(t *testing.T) {
	s := &Stack{config: Config{MemoryLimit: 1 << 20}, done: make(chan struct{}), outgoing: make(chan *ownedBuffer, 1)}
	s.scheduler = newScheduler(s.done)
	s.buffers.init(s)
	s.outgoing <- nil
	flows := make([]*TCPConn, 5)
	for i := range flows {
		flows[i] = &TCPConn{stack: s, job: timerJob{index: -1}}
		flows[i].waitOutput(1500)
		flows[i].waitOutput(1500) // A retry must not create a second queue entry.
	}
	flows[0].cancelOutputWait()
	flows[2].cancelOutputWait()
	flows[4].cancelOutputWait()
	<-s.outgoing
	for _, i := range []int{1, 3} {
		if s.outputWaiters.head != flows[i] {
			t.Fatal("cancellation corrupted FIFO links")
		}
		s.wakeOutput()
		if !flows[i].outputReady.Load() || flows[i].outputQueued || flows[i].outputPrev != nil || flows[i].outputNext != nil {
			t.Fatal("woken flow retained queue links")
		}
	}
	if s.outputCount.Load() != 0 || s.outputWaiters.Len() != 0 || s.outputWaiters.tail != nil {
		t.Fatal("empty queue retained a flow")
	}
}
