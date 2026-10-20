package trafficcontrol

import (
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestGroupedFairQueueHostIsolationFromFlowMultiplication(t *testing.T) {
	q := NewGroupedFairQueue[int](FairConfig{MaxPackets: 1024, MaxBytes: 1024 * 1400, Quantum: 1400})
	now := time.Now()
	for i := range 480 {
		if !q.Push(1, uint64(i%120), 1400, 1, now, 1) {
			t.Fatal("bulk host admission")
		}
	}
	for range 120 {
		if !q.Push(2, 9, 1400, 2, now, 1) {
			t.Fatal("interactive host admission")
		}
	}
	var one, two int
	for range 200 {
		v, ok, drops := q.Pop(now)
		if !ok || len(drops) > 0 {
			t.Fatalf("unexpected drop: %t %d", ok, len(drops))
		}
		switch v {
		case 1:
			one++
		case 2:
			two++
		default:
			t.Fatal("corrupt packet")
		}
	}
	if one < 85 || one > 115 || two < 85 || two > 115 {
		t.Fatalf("120 parallel flows unfair against one peer: a=%d b=%d", one, two)
	}
	s := q.Stats()
	if s.Packets != 400 || s.Bytes != 400*1400 || s.Flows != 2 {
		t.Fatal(s)
	}
	remaining := q.Drain()
	if len(remaining) != 400 || q.Stats().Packets != 0 {
		t.Fatal("drain lost ownership")
	}
}

func TestGroupedFairQueueCapsCancellationAndAQM(t *testing.T) {
	q := NewGroupedFairQueue[int](FairConfig{MaxPackets: 4, MaxBytes: 2500, Quantum: 1000, Target: time.Millisecond, Interval: time.Millisecond})
	now := time.Now()
	if !q.Push(1, 1, 1000, 1, now, 1) || !q.Push(2, 2, 1000, 2, now, 1) {
		t.Fatal("admission")
	}
	if q.Push(3, 3, 600, 3, now, 1) {
		t.Fatal("byte budget bypass")
	}
	if !q.Push(1, 1, 500, 4, now, 1) {
		t.Fatal("remaining headroom")
	}
	if q.Push(3, 3, 1, 5, now, 1) {
		t.Fatal("packet budget bypass")
	}
	s := q.Stats()
	if s.Packets != 3 || s.Bytes != 2500 || s.Rejected != 2 {
		t.Fatal(s)
	}
	all := q.Drain()
	if len(all) != 3 || q.Stats().Flows != 0 {
		t.Fatal("drain error", all, q.Stats())
	}
}

func TestGroupedFairQueueByteFairnessWithUnequalPacketSizes(t *testing.T) {
	const preloadPerGroup = 2048
	q := NewGroupedFairQueue[int](FairConfig{MaxPackets: 2 * preloadPerGroup, MaxBytes: 8 << 20, Quantum: 1400})
	now := time.Now()
	for range preloadPerGroup {
		if !q.Push(1, 1, 1400, 1, now, 1) || !q.Push(2, 2, 64, 2, now, 1) {
			t.Fatal("preload failed")
		}
	}
	var served [3]int64
	for range 5000 {
		group, ok, drops := q.Pop(now)
		if !ok || len(drops) != 0 {
			t.Fatalf("unexpected pop: ok=%t drops=%d", ok, len(drops))
		}
		size := 1400
		if group == 2 {
			size = 64
		}
		served[group] += int64(size)
		if !q.Push(uint64(group), uint64(group), size, group, now, 1) {
			t.Fatal("steady-state refill failed")
		}
	}
	difference := served[1] - served[2]
	if difference < 0 {
		difference = -difference
	}
	if total := served[1] + served[2]; difference*100 > total*10 {
		t.Fatalf("host byte fairness exceeded 10%%: large=%d small=%d", served[1], served[2])
	}
}

func TestGroupedFairQueueConcurrentOwnership(t *testing.T) {
	q := NewGroupedFairQueue[int](FairConfig{MaxPackets: 1000, MaxBytes: 1000 * 1400})
	now := time.Now()
	var wg sync.WaitGroup
	for group := range 8 {
		wg.Go(func() {
			for i := range 100 {
				if !q.Push(uint64(group), uint64(i%10), 1400, i, now, 1) {
					t.Error("unexpected admission rejection")
				}
			}
		})
	}
	wg.Wait()
	seen := 0
	for {
		_, ok, dropped := q.Pop(now)
		seen += len(dropped)
		if !ok {
			break
		}
		seen++
	}
	if seen != 800 || q.Stats().Packets != 0 {
		t.Fatalf("lost ownership: %d", seen)
	}
	runtime.KeepAlive(q)
}

func BenchmarkGroupedFairQueueHostIsolation(b *testing.B) {
	q := NewGroupedFairQueue[int](FairConfig{MaxPackets: 1024, MaxBytes: 1024 * 1500, Quantum: 1514})
	now := time.Now()
	for i := range 1024 {
		q.Push(uint64(i%16), uint64(i), 1400, i, now, 1)
	}
	b.ReportAllocs()
	b.SetBytes(1400)
	b.ResetTimer()
	for i := range b.N {
		_, ok, drops := q.Pop(now)
		if !ok || len(drops) != 0 {
			b.Fatal("pop")
		}
		if !q.Push(uint64(i%16), uint64(i%512), 1400, i, now, 1) {
			b.Fatal("push")
		}
	}
}

func BenchmarkGroupedFairQueueMixedPacketSizes(b *testing.B) {
	const packets = 4096
	b.Run("grouped-drr", func(b *testing.B) {
		q := NewGroupedFairQueue[int](FairConfig{MaxPackets: packets, MaxBytes: 8 << 20, Quantum: 1400})
		now := time.Now()
		for range packets / 2 {
			q.Push(1, 1, 1400, 1, now, 1)
			q.Push(2, 2, 64, 2, now, 1)
		}
		b.ReportAllocs()
		b.ResetTimer()
		var servedBytes int64
		for b.Loop() {
			group, ok, drops := q.Pop(now)
			if !ok || len(drops) != 0 {
				b.Fatal("pop")
			}
			size := 1400
			if group == 2 {
				size = 64
			}
			if !q.Push(uint64(group), uint64(group), size, group, now, 1) {
				b.Fatal("push")
			}
			servedBytes += int64(size)
		}
		if servedBytes == 0 {
			b.Fatal("no bytes served")
		}
	})
	b.Run("fifo-ring", func(b *testing.B) {
		type item struct{ group, size int }
		queue := make([]item, packets)
		for i := range packets / 2 {
			queue[2*i], queue[2*i+1] = item{group: 1, size: 1400}, item{group: 2, size: 64}
		}
		read, write := 0, 0
		b.ReportAllocs()
		b.ResetTimer()
		var servedBytes int64
		for b.Loop() {
			packet := queue[read]
			read = (read + 1) % packets
			queue[write] = packet
			write = (write + 1) % packets
			servedBytes += int64(packet.size)
		}
		if servedBytes == 0 {
			b.Fatal("no bytes served")
		}
	})
}

func TestGroupedAdmissionProtectsNewHostUnderSaturation(t *testing.T) {
	q := NewGroupedFairQueue[int](FairConfig{MaxPackets: 4, MaxBytes: 4 * 1400, Quantum: 1400})
	now := time.Now()
	for range 4 {
		q.Push(1, 1, 1400, 1, now, 1)
	}
	admitted, evicted := q.Admit(2, 2, 64, 2, now, 1)
	if !admitted || len(evicted) != 1 || evicted[0] != 1 {
		t.Fatalf("new host not isolated: admitted=%v evicted=%v", admitted, evicted)
	}
	seen := 0
	for range 4 {
		host, ok, drops := q.Pop(now)
		if !ok || len(drops) > 0 {
			t.Fatal("lost queued ownership")
		}
		if host == 2 {
			seen++
		}
	}
	if seen != 1 || q.Stats().DroppedOverload != 1 || q.Stats().Packets != 0 {
		t.Fatal("shed packet ownership or service lost", q.Stats())
	}
}

func TestGroupedAdmissionReservesSpaceForAnotherFlow(t *testing.T) {
	q := NewGroupedFairQueue[int](FairConfig{MaxPackets: 4, MaxBytes: 5600})
	now := time.Now()
	for range 3 {
		if ok, _ := q.Admit(1, 1, 1400, 1, now, 1); !ok {
			t.Fatal("initial admission")
		}
	}
	if ok, drops := q.Admit(1, 1, 1400, 1, now, 1); ok || len(drops) != 0 {
		t.Fatal("hot flow consumed final descriptor")
	}
	if ok, drops := q.Admit(1, 2, 64, 2, now, 1); !ok || len(drops) != 0 {
		t.Fatalf("new flow starved: %v %v", ok, drops)
	}
	if q.Stats().Packets != 4 || q.Stats().Bytes > 5600 {
		t.Fatal(q.Stats())
	}
}
