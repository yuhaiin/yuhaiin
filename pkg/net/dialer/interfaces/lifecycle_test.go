package interfaces

import (
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netstate"
)

func TestSnapshotFailureRetainsLastKnownPaths(t *testing.T) {
	before := AltNetInterfaces
	t.Cleanup(func() { AltNetInterfaces = before })
	m := netstate.NewManager()
	m.Apply(netstate.Snapshot{Networks: []netstate.Network{{ID: "known", Name: "test", Index: 1, Available: true, Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.2")}}}}, false)
	p := m.Capture("test", netip.Addr{}, 4)
	for _, getter := range []func() ([]Interface, error){
		func() ([]Interface, error) { return nil, errors.New("transient interface discovery failure") },
		func() ([]Interface, error) {
			return []Interface{{Interface: &net.Interface{Name: "test", Index: 0}}}, nil
		},
	} {
		AltNetInterfaces = getter
		if _, err := m.Refresh(readNetworkSnapshot, true); err == nil || !m.Valid(p) {
			t.Fatal("unknown platform state invalidated last-known usable socket")
		}
	}
}

func TestSharedMonitorOwnershipAndRestart(t *testing.T) {
	var owners monitorOwnerSet
	var starts, stops atomic.Int32
	stopping, allowStop := make(chan struct{}), make(chan struct{})
	factory := func() networkMonitorCloser {
		starts.Add(1)
		return func() {
			if stops.Add(1) == 1 {
				close(stopping)
				<-allowStop
			}
		}
	}
	a, b := owners.acquire(factory), owners.acquire(factory)
	_ = a.Close()
	_ = a.Close()
	if starts.Load() != 1 || stops.Load() != 0 {
		t.Fatal("one core stopped another core's shared monitor")
	}
	done := make(chan struct{})
	go func() { defer close(done); _ = b.Close() }()
	select {
	case <-stopping:
	case <-time.After(time.Second):
		t.Fatal("final owner did not stop monitor")
	}
	restarted := make(chan networkMonitorCloser, 1)
	go func() { restarted <- owners.acquire(factory) }()
	if starts.Load() != 1 {
		t.Fatal("new callbacks overlapped old monitor shutdown")
	}
	close(allowStop)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("monitor shutdown hung")
	}
	select {
	case c := <-restarted:
		_ = c.Close()
	case <-time.After(time.Second):
		t.Fatal("monitor could not restart")
	}
	if starts.Load() != 2 || stops.Load() != 2 {
		t.Fatal("monitor reference count leaked")
	}
}
