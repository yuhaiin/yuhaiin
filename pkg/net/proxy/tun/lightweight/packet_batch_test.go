package lightweight

import (
	"errors"
	"net"
	"syscall"
	"testing"
	"time"
)

type batchTestWriter struct {
	PacketBufferWriter
	size  int
	write func([]PacketBuffer) (int, error)
}

func (w *batchTestWriter) PacketBatchSize() int                           { return w.size }
func (w *batchTestWriter) WritePacketBatch(b []PacketBuffer) (int, error) { return w.write(b) }

func batchTestStack(t *testing.T, n int) (*Stack, []*ownedBuffer) {
	t.Helper()
	s := &Stack{config: Config{MemoryLimit: 1 << 20}, done: make(chan struct{}), outgoing: make(chan *ownedBuffer, n)}
	s.scheduler = newScheduler(s.done)
	s.buffers.init(s)
	all := make([]*ownedBuffer, n)
	for i := range n {
		b, e := s.buffers.get(64)
		if e != nil {
			t.Fatal(e)
		}
		b.offset = 4
		b.data[4] = byte(i)
		all[i] = b
		s.outgoing <- b
	}
	t.Cleanup(func() {
		for len(s.outgoing) > 0 {
			(<-s.outgoing).release()
		}
		s.buffers.close()
		if s.memory.Load() != 0 {
			t.Fatal("batch retained packet leases", s.memory.Load())
		}
	})
	return s, all
}

func TestPacketBatchWriterRetriesOnlySuffix(t *testing.T) {
	s, all := batchTestStack(t, 32)
	accepted, calls := 0, 0
	w := &batchTestWriter{size: 16}
	w.write = func(p []PacketBuffer) (int, error) {
		calls++
		if calls == 1 && len(p) != 16 {
			t.Fatal("did not drain available batch", len(p))
		}
		if calls == 2 && len(p) != 13 {
			t.Fatal("did not retry suffix", len(p))
		}
		n := len(p)
		var err error
		if calls == 1 {
			n = 3
			err = syscall.EAGAIN
		}
		for _, b := range p[:n] {
			if b.Data[b.Offset] != byte(accepted) {
				t.Fatal("replayed or reordered packet", accepted, b.Data[b.Offset])
			}
			accepted++
		}
		if accepted == 32 {
			close(s.done)
		}
		return n, err
	}
	s.writeBatchLoop(w)
	if accepted != 32 || s.packetsOut.Load() != 32 {
		t.Fatal(accepted, s.packetsOut.Load())
	}
	for _, b := range all {
		if b.refs != 0 {
			t.Fatal("lease not released")
		}
	}
}

func TestPacketBatchWriterDoesNotWaitForMorePackets(t *testing.T) {
	s, _ := batchTestStack(t, 1)
	w := &batchTestWriter{size: 128, write: func(p []PacketBuffer) (int, error) {
		if len(p) != 1 {
			t.Error("one packet delayed for batch")
		}
		close(s.done)
		return 1, nil
	}}
	finished := make(chan struct{})
	go func() { s.writeBatchLoop(w); close(finished) }()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("waited to form a batch")
	}
}

func TestPacketBatchWriterFatalAndInvalidProgressReleaseBuffers(t *testing.T) {
	for _, n := range []int{-1, 0, 17} {
		t.Run(string(rune(n+100)), func(t *testing.T) {
			s, all := batchTestStack(t, 16)
			s.writeBatchLoop(&batchTestWriter{size: 16, write: func([]PacketBuffer) (int, error) { return n, net.ErrClosed }})
			for _, b := range all {
				if b.refs != 0 {
					t.Fatal("fatal write retained buffer")
				}
			}
		})
	}
}

func TestPacketBatchWriterCloseInterruptsRetry(t *testing.T) {
	s, all := batchTestStack(t, 16)
	entered := make(chan struct{}, 1)
	w := &batchTestWriter{size: 16, write: func([]PacketBuffer) (int, error) {
		select {
		case entered <- struct{}{}:
		default:
		}
		return 0, syscall.ENOBUFS
	}}
	done := make(chan struct{})
	go func() { s.writeBatchLoop(w); close(done) }()
	<-entered
	close(s.done)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("close stuck behind batch retry")
	}
	for _, b := range all {
		if b.refs != 0 {
			t.Fatal("close retained buffer")
		}
	}
}

func TestPacketBatchWriterZeroProgressStops(t *testing.T) {
	s, _ := batchTestStack(t, 1)
	calls := 0
	s.writeBatchLoop(&batchTestWriter{size: 16, write: func([]PacketBuffer) (int, error) { calls++; return 0, nil }})
	if calls != 1 {
		t.Fatal("zero progress spun", calls)
	}
}

func TestPacketBatchWriterIgnoresErrorAfterCompletePrefix(t *testing.T) {
	s, _ := batchTestStack(t, 1)
	s.writeBatchLoop(&batchTestWriter{size: 16, write: func(p []PacketBuffer) (int, error) { close(s.done); return len(p), errors.New("trailing error") }})
	if s.packetsOut.Load() != 1 {
		t.Fatal("accepted packet not counted")
	}
}
