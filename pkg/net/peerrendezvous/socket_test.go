package peerrendezvous

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"
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
		s := NewSocket(&filteredSocket{PacketConn: raw, allowed: make(map[string]bool)}, server.LocalAddr().(*net.UDPAddr).AddrPort(), key, role)
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
}
