package lightweight

import (
	"context"
	"go.uber.org/goleak"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestThousandConnectionsReclaimed(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	a, b := stackPair(t)
	l, err := b.ListenTCP(netip.MustParseAddrPort("192.0.2.2:8080"))
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan []net.Conn, 1)
	go func() {
		cs := make([]net.Conn, 0, 1000)
		for range 1000 {
			c, err := l.Accept()
			if err != nil {
				break
			}
			cs = append(cs, c)
		}
		accepted <- cs
	}()
	clients := make([]net.Conn, 0, 1000)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	for range 1000 {
		c, err := a.DialContextTCP(ctx, netip.MustParseAddrPort("192.0.2.2:8080"))
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, c)
	}
	peers := <-accepted
	if len(peers) != 1000 {
		t.Fatal("missing accepted connections")
	}
	if a.Stats().Connections != 1000 || b.Stats().Connections != 1000 {
		t.Fatal("incorrect idle flow count")
	}
	var wg sync.WaitGroup
	for i, c := range clients {
		wg.Go(func() { _ = c.Close(); _ = peers[i].Close() })
	}
	wg.Wait()
	_ = l.Close()
	_ = a.Close()
	_ = b.Close()
	if a.Stats().MemoryBytes != 0 || b.Stats().MemoryBytes != 0 || a.Stats().Connections != 0 || b.Stats().Connections != 0 {
		t.Fatalf("retained resources: %+v %+v", a.Stats(), b.Stats())
	}
}

func TestUDPConcurrentCloseAndForwardBounds(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	m, _ := memoryPair()
	s, err := New(Config{Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, ForwardUDP: true, QueuePackets: 1}, m)
	if err != nil {
		t.Fatal(err)
	}
	u, err := s.ListenUDP(netip.MustParseAddrPort("192.0.2.1:80"))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 1000 {
			_, _ = u.WriteTo([]byte("x"), net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.2:80")))
		}
	})
	wg.Go(func() { _ = u.Close(); _ = s.Close() })
	wg.Wait()
	_ = s.Close()
	if s.Stats().MemoryBytes != 0 {
		t.Fatalf("close/write leak: %+v", s.Stats())
	}
}
