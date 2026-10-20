package trafficcontrol

import (
	"testing"
	"time"
)

func BenchmarkFairQueuePushPop(b *testing.B) {
	for _, flows := range []int{1, 16, 256} {
		b.Run("flows="+itoa(flows), func(b *testing.B) {
			q := NewFairQueue[int](FairConfig{MaxPackets: 4096, MaxBytes: 16 << 20, Quantum: 1514})
			now := time.Now()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if !q.Push(uint64(i%flows), 1400, i, now) {
					b.Fatal("capacity")
				}
				_, ok, drops := q.Pop(now)
				if !ok || len(drops) != 0 {
					b.Fatal("dequeue")
				}
			}
		})
	}
}
func BenchmarkGovernorSession(b *testing.B) {
	g := NewGovernor(Limits{MaxSessions: 65536}, nil)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		l, ok := g.AcquireSession()
		if !ok {
			b.Fatal("limit")
		}
		l.Release()
	}
}
func BenchmarkGovernorPacketAdmit(b *testing.B) {
	g := NewGovernor(Limits{PacketsPerSec: 1000000000, PacketBurst: 1024}, nil)
	now := time.Now()
	b.ReportAllocs()
	for b.Loop() {
		now = now.Add(time.Nanosecond)
		if !g.AdmitPacket(now) {
			b.Fatal("rate limit")
		}
	}
}
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	p := len(b)
	for n > 0 {
		p--
		b[p] = byte(n%10) + '0'
		n /= 10
	}
	return string(b[p:])
}

// BenchmarkFairQueueSaturated mixes flow enqueue and dequeue with a persistent
// multi-flow backlog; PushPop by itself mostly measures the empty-queue path.
func BenchmarkFairQueueSaturated(b *testing.B) {
	for _, flows := range []int{8, 128, 512} {
		b.Run("flows="+itoa(flows), func(b *testing.B) {
			const packets = 1024
			q := NewFairQueue[int](FairConfig{MaxPackets: packets, MaxBytes: packets * 1500, Quantum: 1514})
			now := time.Now()
			for i := range packets {
				if !q.Push(uint64(i%flows), 1400, i, now) {
					b.Fatal("preload")
				}
			}
			b.ReportAllocs()
			b.SetBytes(1400)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, ok, drops := q.Pop(now)
				if !ok || len(drops) != 0 {
					b.Fatal("dequeue")
				}
				if !q.Push(uint64(i%flows), 1400, i, now) {
					b.Fatal("enqueue")
				}
			}
		})
	}
}
func BenchmarkGovernorParallelSession(b *testing.B) {
	g := NewGovernor(Limits{MaxSessions: 1 << 20}, nil)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			lease, ok := g.AcquireSession()
			if !ok {
				b.Fatal("session budget")
			}
			lease.Release()
		}
	})
}

func BenchmarkGroupedFairQueueSparse(b *testing.B) {
	q := NewGroupedFairQueue[int](FairConfig{MaxPackets: 1024, MaxBytes: 4 << 20})
	now := time.Now()
	b.ReportAllocs()
	for b.Loop() {
		if !q.Push(1, 1, 1400, 1, now, 1) {
			b.Fatal("push")
		}
		if _, ok, drops := q.Pop(now); !ok || len(drops) != 0 {
			b.Fatal("pop")
		}
	}
}
