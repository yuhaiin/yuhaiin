package dialer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netstate"
)

func socketManager(t *testing.T) (*netstate.Manager, netstate.Snapshot) {
	t.Helper()
	m := netstate.NewManager()
	s := netstate.Snapshot{Networks: []netstate.Network{{ID: "loopback", Index: 1, Name: "test-lo", Available: true, Addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}}}
	m.Apply(s, false)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); m.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("worker failed to stop")
		}
	})
	return m, s
}

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	l, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	raw, err := net.DialTCP("tcp4", nil, l.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	peer, err := l.AcceptTCP()
	if err != nil {
		raw.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close(); _ = peer.Close() })
	return raw, peer
}

func TestTrackedTCPSurvivesRouteStormAndClosesOnSourceLoss(t *testing.T) {
	m, s := socketManager(t)
	raw, peer := tcpPair(t)
	p := m.Capture("test-lo", netip.Addr{}, 4)
	c, err := trackTCP(m, raw, p, "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for range 1000 {
		m.Apply(s, true)
	}
	if _, err := peer.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := c.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Read(make([]byte, 1)); err != nil {
		t.Fatalf("routine route updates disconnected proxy TCP: %v", err)
	}
	result := make(chan error, 1)
	go func() { _, err := c.Read(make([]byte, 1)); result <- err }()
	m.AddressUnavailable(1, netip.MustParseAddr("127.0.0.1"))
	select {
	case err := <-result:
		if !errors.Is(err, netstate.ErrInvalidated) {
			t.Fatalf("source invalidation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("obsolete TCP remained blocked")
	}
}

func TestPendingDialCanceledOnlyForItsPath(t *testing.T) {
	m, s := socketManager(t)
	p := m.Capture("test-lo", netip.Addr{}, 4)
	ctx, release := pendingDial(t.Context(), m, p)
	defer release()
	for range 100 {
		m.Apply(s, true)
	}
	if ctx.Err() != nil {
		t.Fatal("route update canceled pending dial")
	}
	m.InterfaceUnavailable(1)
	select {
	case <-ctx.Done():
		if !errors.Is(context.Cause(ctx), netstate.ErrInvalidated) {
			t.Fatal(context.Cause(ctx))
		}
	case <-time.After(time.Second):
		t.Fatal("obsolete TCP dial not canceled")
	}
	// A source invalidated while the connect syscall completed cannot be
	// assigned a new lifetime just because the same address reappeared.
	m.Apply(s, false)
	raw, _ := tcpPair(t)
	if c, err := trackTCP(m, raw, p, ""); c != nil || !errors.Is(err, netstate.ErrInvalidated) {
		t.Fatalf("stale dial accepted: %v, %v", c, err)
	}
}

func TestLocalDialDoesNotInheritUnderlyingDefaultNetwork(t *testing.T) {
	m, s := socketManager(t)
	s.Selected = s.Networks[0].ID
	m.Apply(s, false)
	for _, remote := range []string{"127.0.0.1", "::1", "169.254.1.1", "fe80::1"} {
		if p := dialPath(m, "test-lo", netip.Addr{}, netip.MustParseAddr(remote)); p.Known() {
			t.Fatalf("unbound local dial inherited default network: %s", remote)
		}
	}
}

func TestUDPSelectiveCloseAndConcurrentOwnerClose(t *testing.T) {
	m, s := socketManager(t)
	newConn := func() *UDPConn {
		t.Helper()
		raw, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		c, err := trackUDP(m, raw, &Options{InterfaceName: "test-lo"}, m.Capture("test-lo", netip.Addr{}, 4), 4)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	old := newConn()
	for range 1000 {
		m.Apply(s, true)
	}
	if !m.Valid(old.NetworkPath()) {
		t.Fatal("UDP mapping invalidated by route traffic")
	}
	m.InterfaceUnavailable(1)
	m.Apply(s, false)
	fresh := newConn()
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 100 {
			_ = old.Close()
		}
	})
	wg.Go(func() {
		for range 100 {
			m.Apply(s, true)
		}
	})
	wg.Wait()
	if !m.Valid(fresh.NetworkPath()) {
		t.Fatal("stale cleanup affected replacement socket")
	}
	if _, err := fresh.WriteTo([]byte("x"), fresh.LocalAddr()); err != nil {
		t.Fatalf("unaffected replacement UDP closed: %v", err)
	}
}
