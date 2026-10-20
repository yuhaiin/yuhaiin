package inbound

import (
	"errors"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"sync"
	"testing"
)

type failingCloseAccepter struct{ err error }

func (failingCloseAccepter) Interface() string { return "" }
func (a failingCloseAccepter) Close() error    { return a.err }

func TestRemoveRetiresStreamScopeWhenServerCloseFails(t *testing.T) {
	l := &Inbound{handler: NewHandler(nil)}
	lease, ok := l.handler.control.AdmitStream("inbound-a")
	if !ok {
		t.Fatal("stream admission failed")
	}
	l.store.Store("inbound-a", entry{server: failingCloseAccepter{err: errors.New("close failed")}})
	if err := l.Remove("inbound-a"); err == nil {
		t.Fatal("Remove hid the server close failure")
	}
	lease.Release()
	if len(l.handler.control.Status().InboundScopes) != 0 {
		t.Fatal("failed server close left an unleased stream scope")
	}
	_ = l.handler.Close()
}

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
