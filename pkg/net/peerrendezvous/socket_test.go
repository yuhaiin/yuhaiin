package peerrendezvous

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/contract/transport"
)

// This models endpoint-dependent filtering with a stable mapping. The peer
// socket may receive from a destination only after it has sent to that address.
type filteredSocket struct {
	net.PacketConn
	mu      sync.Mutex
	allowed map[string]bool
}

func (s *filteredSocket) WriteTo(p []byte, dst net.Addr) (int, error) {
	s.mu.Lock()
	s.allowed[dst.String()] = true
	s.mu.Unlock()
	return s.PacketConn.WriteTo(p, dst)
}

func (s *filteredSocket) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, from, err := s.PacketConn.ReadFrom(p)
		if err != nil {
			return 0, nil, err
		}
		s.mu.Lock()
		ok := s.allowed[from.String()]
		s.mu.Unlock()
		if ok {
			return n, from, nil
		}
	}
}

func TestSocketPunchAndRelearnEndpoint(t *testing.T) {
	listen := func() *net.UDPConn {
		t.Helper()
		s, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	const budget = 9 * time.Second
	ctx, cancel := context.WithTimeout(t.Context(), budget)
	defer cancel()
	key := [32]byte{1}
	server := listen()
	coord := Serve(server, [][32]byte{key})
	t.Cleanup(func() { _ = coord.Close() })
	start := func(role Role) (*Socket, <-chan []byte) {
		t.Helper()
		raw := listen()
		s := NewSocket(&filteredSocket{PacketConn: raw, allowed: make(map[string]bool)}, server.LocalAddr().(*net.UDPAddr).AddrPort(), key, role, nil)
		data := make(chan []byte, 1)
		exited := make(chan struct{})
		go func() {
			defer close(exited)
			defer close(data)
			var buf [2048]byte
			for {
				n, _, err := s.ReadFrom(buf[:])
				if err != nil {
					return
				}
				select {
				case data <- bytes.Clone(buf[:n]):
				case <-s.stopped:
					return
				}
			}
		}()
		t.Cleanup(func() { _ = s.Close(); <-exited })
		return s, data
	}
	a, _ := start(Dialer)
	b, input := start(Publisher)
	check := func(peer *Socket, data <-chan []byte) {
		t.Helper()
		if err := peer.WaitReady(ctx); err != nil {
			t.Fatal(err)
		}
		packet := bytes.Repeat([]byte{42}, 128)
		for {
			// WriteTo must ignore its WireGuard endpoint argument, even when
			// that argument names the coordinator.
			if _, err := a.WriteTo(packet, server.LocalAddr()); err != nil {
				t.Fatal(err)
			}
			select {
			case payload, ok := <-data:
				if !ok || !bytes.Equal(payload, packet) {
					t.Fatal("direct payload changed or socket stopped")
				}
				return
			case <-time.After(30 * time.Millisecond):
			case <-ctx.Done():
				t.Fatal(io.ErrNoProgress)
			}
		}
	}
	check(b, input)
	_ = b.Close()
	replacement, input := start(Publisher)
	check(replacement, input)

	pairID := transport.PeerPairIDString(key)
	coordinator := server.LocalAddr().(*net.UDPAddr).AddrPort()
	before := coord.Pairs()[pairID]
	if !before.Dialer.IsValid() || !before.Publisher.IsValid() {
		t.Fatalf("missing registered peers: %+v", before)
	}
	result, err := Lookup(ctx, coordinator, key)
	if err != nil || result.Endpoint != before.Publisher {
		t.Fatalf("read-only lookup: %+v, %v", result, err)
	}
	if after := coord.Pairs()[pairID]; after != before {
		t.Fatalf("lookup replaced the real tunnel registration: %+v", after)
	}

	coord.SetBlocked([]string{pairID})
	deadline := time.Now().Add(4 * time.Second)
	for a.peer.Load() != nil || replacement.peer.Load() != nil {
		if time.Now().After(deadline) {
			t.Fatal("blocked pairing retained an active data path")
		}
		time.Sleep(20 * time.Millisecond)
	}
	blockedPayload := bytes.Repeat([]byte{43}, 128)
	if _, err := a.WriteTo(blockedPayload, server.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	select {
	case payload := <-input:
		if bytes.Equal(payload, blockedPayload) {
			t.Fatal("data arrived after the pair was blocked")
		}
	case <-time.After(40 * time.Millisecond):
	}
	coord.SetBlocked(nil)
	ctx, resumeCancel := context.WithTimeout(t.Context(), budget)
	defer resumeCancel()
	for replacement.peer.Load() == nil {
		if ctx.Err() != nil {
			t.Fatal("unblocked peer did not relearn the direct path")
		}
		time.Sleep(20 * time.Millisecond)
	}
	check(replacement, input)
}

func TestSocketDropsOfflinePeerAndFinishedExchange(t *testing.T) {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	key := [32]byte{5}
	coordinator := netip.MustParseAddrPort("127.0.0.1:9")
	s := NewSocket(pc, coordinator, key, Dialer, nil)
	t.Cleanup(func() { _ = s.Close() })
	// reply answers the exchange the socket has open. reopen models its next hello.
	reply := func(endpoint netip.AddrPort, reopen bool) {
		t.Helper()
		var m message
		copy(m[:4], magic)
		m[4], m[5] = discovered, byte(Dialer)
		copy(m[8:24], s.id[:])
		s.mu.Lock()
		if reopen {
			s.pending = true
		}
		copy(m[24:40], s.nonce[:])
		s.mu.Unlock()
		m.setEndpoint(endpoint)
		m.sign(key)
		s.receiveControl(m, net.UDPAddrFromAddrPort(coordinator))
	}
	peer := func() netip.AddrPort {
		if p := s.peer.Load(); p != nil {
			return p.AddrPort()
		}
		return netip.AddrPort{}
	}
	for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(time.Millisecond) {
		s.mu.Lock()
		started := s.pending
		s.mu.Unlock()
		if started {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("socket did not start an exchange")
		}
	}
	first := netip.MustParseAddrPort("127.0.0.1:2001")
	reply(first, false)
	if peer() != first {
		t.Fatalf("peer %v, want %v", peer(), first)
	}
	reply(netip.MustParseAddrPort("127.0.0.1:2002"), false)
	if peer() != first {
		t.Fatalf("a reply to a finished exchange replaced the peer with %v", peer())
	}
	for i := 1; i < offlineAfter; i++ {
		reply(netip.AddrPort{}, true)
		if peer() != first {
			t.Fatalf("peer dropped after %d empty registrations", i)
		}
	}
	reply(netip.AddrPort{}, true)
	if peer().IsValid() {
		t.Fatalf("offline peer %v kept its direct path", peer())
	}
}
