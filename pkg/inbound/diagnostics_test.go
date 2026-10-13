package inbound

import (
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"sync"
	"testing"
)

func TestListenerSnapshotLifecycle(t *testing.T) {
	l := &Inbound{}
	if registered, _, _, _ := l.ListenerSnapshot("missing"); registered {
		t.Fatal("missing listener was reported active")
	}
	counts := &ingressCounters{}
	counts.streams.Store(2)
	counts.packets.Store(3)
	counts.pings.Store(4)
	l.store.Store("tun", entry{server: &routeAccepterStub{}, counters: counts})
	registered, streams, packets, pings := l.ListenerSnapshot("tun")
	if !registered || streams != 2 || packets != 3 || pings != 4 {
		t.Fatalf("snapshot: %t %d %d %d", registered, streams, packets, pings)
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 1000 {
			counts.packets.Add(1)
		}
	})
	wg.Go(func() {
		for range 1000 {
			l.ListenerSnapshot("tun")
		}
	})
	wg.Wait()
	l.mu.Lock()
	l.closed = true
	l.mu.Unlock()
	if registered, _, _, _ := l.ListenerSnapshot("tun"); registered {
		t.Fatal("closed runtime was reported active")
	}
}

func BenchmarkIngressCounter(b *testing.B) {
	var counts ingressCounters
	for b.Loop() {
		counts.packets.Add(1)
	}
}

func TestRuntimeHistoryIsBoundedAndIngressCountsAreReportedPrecisely(t *testing.T) {
	l := &Inbound{}
	for range 120 {
		l.recordState("local", "starting", "")
		l.recordState("local", "running", "")
	}
	if len(l.states["local"].events) != 100 {
		t.Fatal("unbounded history")
	}
	counts := &ingressCounters{}
	counts.streams.Store(9007199254740993)
	counts.packets.Store(3)
	counts.pings.Store(4)
	l.store.Store("local", entry{server: &routeAccepterStub{}, counters: counts})
	got := l.runtimeStatus(contract.Inbound{ID: "local", Name: "Local", Enabled: true})
	if got.Status != "running" || got.Statistics.AcceptedStreams != "9007199254740993" || got.Statistics.ReceivedPackets != "3" || got.Statistics.ReceivedPings != "4" {
		t.Fatalf("status = %+v", got)
	}
}
