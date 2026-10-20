package lightweight

import (
	"net/netip"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol"
)

func TestFairOutputInterleavesFlowsAndReleasesBuffers(t *testing.T) {
	s := &Stack{
		config: Config{MemoryLimit: 1 << 20}, done: make(chan struct{}),
	}
	s.initOutput(trafficcontrol.SchedulerFair, 64, 64<<10)
	s.scheduler = newScheduler(s.done)
	s.buffers.init(s)
	a, b := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
	push := func(port uint16, sequence int) {
		t.Helper()
		p, err := s.buffers.get(1024)
		if err != nil {
			t.Fatal(err)
		}
		fillIPHeader(p.data, a, b, 6, uint16(sequence), 20)
		p.data[20], p.data[21] = byte(port>>8), byte(port)
		p.data[22], p.data[23] = 0, 80
		if err := s.emitOwned(p); err != nil {
			p.release()
			t.Fatal(err)
		}
	}
	for i := range 24 {
		push(1000, uint16ToInt(i))
	}
	for i := range 6 {
		push(2000, 100+i)
	}
	firstInteractive := -1
	seenBulk, seenInteractive := 0, 0
	for i := range 30 {
		p, ok := s.output.Dequeue(false)
		if !ok {
			t.Fatal("missing packet", i)
		}
		port := uint16(p.data[20])<<8 | uint16(p.data[21])
		switch port {
		case 1000:
			seenBulk++
		case 2000:
			seenInteractive++
			if firstInteractive < 0 {
				firstInteractive = i
			}
		default:
			t.Fatal("unexpected flow")
		}
		p.release()
	}
	if firstInteractive > 2 || seenBulk != 24 || seenInteractive != 6 {
		t.Fatalf("fairness: interactive=%d bulk=%d interactiveCount=%d", firstInteractive, seenBulk, seenInteractive)
	}
	if got := s.Stats(); got.OutputQueuedPackets != 0 || got.OutputQueuedBytes != 0 {
		t.Fatal(got)
	}
	s.output.Close()
	close(s.done)
	s.buffers.close()
	if bytes := s.memory.Load(); bytes != 0 {
		t.Fatal("unreleased output memory", bytes)
	}
}

func uint16ToInt(n int) int { return n }

func TestFairOutputNoOverAdmission(t *testing.T) {
	s := &Stack{config: Config{MemoryLimit: 1 << 20}, done: make(chan struct{})}
	s.initOutput(trafficcontrol.SchedulerFair, 1, 128)
	s.scheduler = newScheduler(s.done)
	s.buffers.init(s)
	for i := range 2 {
		p, err := s.buffers.get(64)
		if err != nil {
			t.Fatal(err)
		}
		p.data[0] = 0x01
		err = s.emitOwned(p)
		if (err == nil) != (i == 0) {
			t.Fatalf("admission iteration=%d err=%v", i, err)
		}
		if err != nil {
			p.release()
		}
	}
	if stats := s.Stats(); stats.OutputQueuedPackets != 1 || stats.OutputRejected != 1 {
		t.Fatal(stats)
	}
	for _, p := range s.output.Drain() {
		p.release()
	}
	s.output.Close()
	close(s.done)
	s.buffers.close()
	if s.memory.Load() != 0 {
		t.Fatal("leaked bytes", s.memory.Load())
	}
}

func TestFairOutputPreservesBatchOrder(t *testing.T) {
	s, _ := batchTestStack(t, 32)
	packets := s.output.Drain()
	s.initOutput(trafficcontrol.SchedulerFair, 33, 64<<10)
	for _, p := range packets {
		if !s.output.Enqueue(p) {
			t.Fatal("queue full")
		}
	}
	accepted := 0
	w := &batchTestWriter{size: 16}
	w.write = func(ps []PacketBuffer) (int, error) {
		for _, p := range ps {
			if p.Data[p.Offset] != byte(accepted) {
				t.Fatalf("batch replay/reorder at %d", accepted)
			}
			accepted++
		}
		if accepted == 32 {
			s.output.Close()
			close(s.done)
		}
		return len(ps), nil
	}
	s.writeBatchLoop(w)
	if accepted != 32 || s.Stats().OutputQueuedPackets != 0 {
		t.Fatal(accepted, s.Stats())
	}
}

func BenchmarkOutputFlowHashIPv4(b *testing.B) {
	packet := &ownedBuffer{data: make([]byte, 1500)}
	packet.data[0] = 0x45
	packet.data[9] = 6
	packet.data[12], packet.data[16] = 10, 20
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = outputFlowHash(packet)
	}
}

func outputHostHash(p *ownedBuffer) uint64  { return trafficcontrol.HostHash(outputBytes(p)) }
func outputFlowHash(p *ownedBuffer) uint64  { return trafficcontrol.FlowHash(outputBytes(p)) }
func outputPacketWeight(p *ownedBuffer) int { return trafficcontrol.PacketWeight(outputBytes(p)) }
