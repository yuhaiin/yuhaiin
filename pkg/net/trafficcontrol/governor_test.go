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
		wg.Go(func() {
			first.Release()
			second.Release()
		})
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
		wg.Go(func() {
			<-start
			if l, ok := g.AcquireSession(); ok {
				success <- l
			}
		})
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
	first, second, overflow := g.AdmitPacket(now), g.AdmitPacket(now), g.AdmitPacket(now)
	if !first || !second || overflow {
		t.Fatal("burst not enforced")
	}
	after := now.Add(10 * time.Millisecond)
	refilled, again := g.AdmitPacket(after), g.AdmitPacket(after)
	if !refilled || again {
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
		wg.Go(func() {
			if g.ReserveQueueBytes(128) {
				success <- struct{}{}
			}
		})
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

func TestSessionCreationRateLimitDoesNotAffectExistingLease(t *testing.T) {
	g := NewGovernor(Limits{MaxSessions: 4, SessionsPerSec: 2, SessionBurst: 2}, nil)
	one, ok := g.AcquireSession()
	if !ok {
		t.Fatal("first session denied")
	}
	two, ok := g.AcquireSession()
	if !ok {
		t.Fatal("second session denied")
	}
	two.Release()
	if _, ok := g.AcquireSession(); ok {
		t.Fatal("rate limit bypassed despite available concurrency")
	}
	if got := g.Snapshot(); got.Sessions != 1 || got.DeniedRateSessions != 1 {
		t.Fatal(got)
	}
	// Pretend a second elapsed without sleeping or depending on a wall clock.
	g.mu.Lock()
	g.sessionLast = g.sessionLast.Add(-time.Second)
	g.mu.Unlock()
	three, ok := g.AcquireSession()
	if !ok {
		t.Fatal("new budget was not replenished")
	}
	one.Release()
	three.Release()
	if got := g.Snapshot(); got.Sessions != 0 {
		t.Fatal(got)
	}
}

func TestGovernorPendingTaskCapAndRelease(t *testing.T) {
	root := NewGovernor(Limits{MaxPendingTasks: 2}, nil)
	child := NewGovernor(Limits{MaxPendingTasks: 1}, root)
	if !child.ReservePendingTask() {
		t.Fatal("reserve")
	}
	if child.ReservePendingTask() {
		t.Fatal("child cap bypass")
	}
	if !root.ReservePendingTask() {
		t.Fatal("root second task denied")
	}
	if root.ReservePendingTask() {
		t.Fatal("parent cap bypass")
	}
	if stats := root.Snapshot(); stats.PendingTasks != 2 || stats.DeniedPending == 0 {
		t.Fatal(stats)
	}
	child.ReleasePendingTask()
	root.ReleasePendingTask()
	if stats := root.Snapshot(); stats.PendingTasks != 0 {
		t.Fatal(stats)
	}
}

func TestOverQuotaChildCannotConsumeParentAdmissionTokens(t *testing.T) {
	root := NewGovernor(Limits{MaxSessions: 10, SessionsPerSec: 2, SessionBurst: 2, PacketsPerSec: 2, PacketBurst: 2}, nil)
	noisy := NewGovernor(Limits{MaxSessions: 1, SessionsPerSec: 1, SessionBurst: 1, PacketsPerSec: 1, PacketBurst: 1}, root)
	quiet := NewGovernor(Limits{MaxSessions: 2, SessionsPerSec: 1, SessionBurst: 1, PacketsPerSec: 1, PacketBurst: 1}, root)
	busy, ok := noisy.AcquireSession()
	if !ok {
		t.Fatal("first connection")
	}
	for range 100 {
		if lease, allowed := noisy.AcquireSession(); allowed {
			lease.Release()
			t.Fatal("over quota child admitted")
		}
	}
	healthy, ok := quiet.AcquireSession()
	if !ok {
		t.Fatal("noisy child starved healthy parent session tokens")
	}
	now := time.Unix(300, 0)
	if !noisy.AdmitPacket(now) {
		t.Fatal("first packet")
	}
	for range 100 {
		if noisy.AdmitPacket(now) {
			t.Fatal("noisy PPS bypass")
		}
	}
	if !quiet.AdmitPacket(now) {
		t.Fatal("noisy child consumed healthy parent's packet quota")
	}
	busy.Release()
	healthy.Release()
	if root.Snapshot().Sessions != 0 {
		t.Fatal("session leakage", root.Snapshot())
	}
}
