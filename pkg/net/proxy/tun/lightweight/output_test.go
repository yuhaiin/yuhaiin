package lightweight

import (
	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol"
	"testing"
)

func TestOutputWakesAfterDescriptorBecomesEvictable(t *testing.T) {
	s := &Stack{config: Config{MemoryLimit: 1 << 20}, done: make(chan struct{})}
	s.initOutput(trafficcontrol.SchedulerFIFO, 1, 1<<20)
	s.scheduler = newScheduler(s.done)
	s.buffers.init(s)
	owner, err := s.buffers.get(1024)
	if err != nil || !s.reserve(segmentCharge) {
		t.Fatalf("reserve: %v", err)
	}
	owner.hold() // Other outstanding views keep the payload allocation live.
	v := s.buffers.takeSegment()
	*v = sendSegment{owner: owner, data: owner.data[:64]}
	rest := int(s.config.MemoryLimit - s.memory.Load())
	if !s.reserve(rest) {
		t.Fatal("fill memory budget")
	}
	waiter := &TCPConn{stack: s, job: timerJob{index: -1}}
	waiter.waitOutput(64)
	if waiter.outputReady.Load() {
		t.Fatal("full allocation budget admitted output")
	}
	s.buffers.releaseSegment(v)
	if !waiter.outputReady.Load() || s.outputCount.Load() != 0 {
		t.Fatal("evictable metadata capacity failed to wake output")
	}
	owner.release()
	s.release(rest)
	s.buffers.close()
	if s.memory.Load() != 0 {
		t.Fatal("metadata-pressure test leaked reservation")
	}
}

func TestOutputCapacityAndFIFO(t *testing.T) {
	s := &Stack{config: Config{MemoryLimit: 1 << 20}, done: make(chan struct{})}
	s.initOutput(trafficcontrol.SchedulerFIFO, 1, 1<<20)
	s.scheduler = newScheduler(s.done)
	s.buffers.init(s)
	first := &TCPConn{stack: s, job: timerJob{index: -1}}
	second := &TCPConn{stack: s, job: timerJob{index: -1}}
	s.output.Enqueue(nil)
	first.waitOutput(1500)
	second.waitOutput(1500)
	for range 100 {
		s.wakeOutput()
	}
	if first.outputReady.Load() || second.outputReady.Load() || len(s.scheduler.jobs) != 0 {
		t.Fatal("full output queue repeatedly woke blocked flows")
	}
	s.output.Dequeue(false)
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
	s := &Stack{config: Config{MemoryLimit: 1 << 20}, done: make(chan struct{})}
	s.initOutput(trafficcontrol.SchedulerFIFO, 1, 1<<20)
	s.scheduler = newScheduler(s.done)
	s.buffers.init(s)
	s.output.Enqueue(nil)
	flows := make([]*TCPConn, 5)
	for i := range flows {
		flows[i] = &TCPConn{stack: s, job: timerJob{index: -1}}
		flows[i].waitOutput(1500)
		flows[i].waitOutput(1500) // A retry must not create a second queue entry.
	}
	flows[0].cancelOutputWait()
	flows[2].cancelOutputWait()
	flows[4].cancelOutputWait()
	s.output.Dequeue(false)
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
