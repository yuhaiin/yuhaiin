package trafficcontrol

import (
	"sync"
	"testing"
	"time"
)

func TestGovernorHierarchyAndRelease(t *testing.T) {
	root := NewGovernor(Limits{MaxSessions: 2, MaxQueueBytes: 100}, nil)
	a := NewGovernor(Limits{MaxSessions: 1, MaxQueueBytes: 60}, root)
	b := NewGovernor(Limits{MaxSessions: 2, MaxQueueBytes: 80}, root)
	first, ok := a.AcquireSession()
	if !ok {
		t.Fatal("first admission failed")
	}
	if _, ok := a.AcquireSession(); ok {
		t.Fatal("child session cap bypassed")
	}
	second, ok := b.AcquireSession()
	if !ok {
		t.Fatal("second admission failed")
	}
	if _, ok := b.AcquireSession(); ok {
		t.Fatal("parent session cap bypassed")
	}
	if !a.ReserveQueueBytes(60) || b.ReserveQueueBytes(50) {
		t.Fatal("hierarchical byte cap")
	}
	if got := root.Snapshot(); got.Sessions != 2 || got.QueueBytes != 60 || got.DeniedSessions == 0 {
		t.Fatalf("bad snapshot: %+v", got)
	}
	a.ReleaseQueueBytes(60)
	if !b.ReserveQueueBytes(50) {
		t.Fatal("rolled back parent reservation leaked")
	}
	b.ReleaseQueueBytes(50)
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() { defer wg.Done(); first.Release(); second.Release() }()
	}
	wg.Wait()
	if got := root.Snapshot(); got.Sessions != 0 || got.QueueBytes != 0 {
		t.Fatalf("leaked %+v", got)
	}
}

func TestGovernorConcurrentLimit(t *testing.T) {
	g := NewGovernor(Limits{MaxSessions: 32}, nil)
	var wg sync.WaitGroup
	start := make(chan struct{})
	success := make(chan *Session, 512)
	for range 512 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if l, ok := g.AcquireSession(); ok {
				success <- l
			}
		}()
	}
	close(start)
	wg.Wait()
	close(success)
	n := 0
	for l := range success {
		n++
		l.Release()
	}
	if n != 32 || g.Snapshot().Sessions != 0 {
		t.Fatalf("admitted %d, stats=%+v", n, g.Snapshot())
	}
}
func TestPacketTokenBudget(t *testing.T) {
	g := NewGovernor(Limits{PacketsPerSec: 100, PacketBurst: 2}, nil)
	now := time.Unix(100, 0)
	if !g.AdmitPacket(now) || !g.AdmitPacket(now) || g.AdmitPacket(now) {
		t.Fatal("burst not enforced")
	}
	if !g.AdmitPacket(now.Add(10*time.Millisecond)) || g.AdmitPacket(now.Add(10*time.Millisecond)) {
		t.Fatal("tokens not refilled")
	}
	if g.Snapshot().DeniedPackets != 2 {
		t.Fatal(g.Snapshot())
	}
}
func TestQueueBytesConcurrentAdmission(t *testing.T) {
	g := NewGovernor(Limits{MaxQueueBytes: 1024}, nil)
	var wg sync.WaitGroup
	success := make(chan struct{}, 64)
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if g.ReserveQueueBytes(128) {
				success <- struct{}{}
			}
		}()
	}
	wg.Wait()
	close(success)
	count := 0
	for range success {
		count++
		g.ReleaseQueueBytes(128)
	}
	if count != 8 || g.Snapshot().QueueBytes != 0 {
		t.Fatalf("reserved %d, stats %+v", count, g.Snapshot())
	}
}
