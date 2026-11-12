package peerrendezvous

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type simulatedDatagram struct {
	data []byte
	from netip.AddrPort
}

type simulatedLAN struct {
	endpoints map[netip.AddrPort]*simulatedUDPSocket
	lan       atomic.Bool
	hairpin   atomic.Bool
}

type simulatedUDPSocket struct {
	net.PacketConn
	network *simulatedLAN
	local   netip.AddrPort
	public  netip.AddrPort
	in      chan simulatedDatagram
	done    chan struct{}
	once    sync.Once
}

func (n *simulatedLAN) socket(local, public string) *simulatedUDPSocket {
	s := &simulatedUDPSocket{
		network: n, local: netip.MustParseAddrPort(local), public: netip.MustParseAddrPort(public),
		in: make(chan simulatedDatagram, 64), done: make(chan struct{}),
	}
	n.endpoints[s.local], n.endpoints[s.public] = s, s
	return s
}

func (s *simulatedUDPSocket) LocalAddr() net.Addr { return net.UDPAddrFromAddrPort(s.local) }

func (s *simulatedUDPSocket) Close() error {
	s.once.Do(func() { close(s.done) })
	return nil
}

func (s *simulatedUDPSocket) WriteTo(p []byte, dst net.Addr) (int, error) {
	to := dst.(*net.UDPAddr).AddrPort()
	target := s.network.endpoints[to]
	if target == nil {
		return len(p), nil
	}
	from := s.public
	if s.local != s.public && target.local != target.public {
		if to == target.local {
			if !s.network.lan.Load() {
				return len(p), nil
			}
			from = s.local
		} else if !s.network.hairpin.Load() {
			return len(p), nil
		}
	}
	select {
	case target.in <- simulatedDatagram{bytes.Clone(p), from}:
	case <-target.done:
	case <-s.done:
		return 0, net.ErrClosed
	}
	return len(p), nil
}

func (s *simulatedUDPSocket) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case msg := <-s.in:
		return copy(p, msg.data), net.UDPAddrFromAddrPort(msg.from), nil
	case <-s.done:
		return 0, nil, net.ErrClosed
	}
}

func TestSocketPrefersLANAndFallsBackToPublicMapping(t *testing.T) {
	t.Run("no NAT loopback", func(t *testing.T) {
		t.Parallel()
		testLANPaths(t, false)
	})
	t.Run("with NAT loopback", func(t *testing.T) {
		t.Parallel()
		testLANPaths(t, true)
	})
}

func testLANPaths(t *testing.T, hairpin bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 16*time.Second)
	defer cancel()
	network := &simulatedLAN{endpoints: make(map[netip.AddrPort]*simulatedUDPSocket)}
	network.lan.Store(true)
	network.hairpin.Store(hairpin)
	public := network.socket("203.0.113.1:51821", "203.0.113.1:51821")
	client := network.socket("192.168.50.2:1234", "198.51.100.1:2134")
	gateway := network.socket("192.168.50.3:5678", "198.51.100.1:8765")
	key := [32]byte{1}
	coordinator := Serve(public, [][32]byte{key})
	t.Cleanup(func() { _ = coordinator.Close() })

	start := func(pc *simulatedUDPSocket, role Role) (*Socket, <-chan simulatedDatagram) {
		s := NewManagedSocket(pc, public.local, key, role, nil, nil, nil, netip.PrefixFrom(pc.local.Addr(), 24))
		delivered := make(chan simulatedDatagram, 4)
		done := make(chan struct{})
		go func() {
			defer close(done)
			var buf [2048]byte
			for {
				n, from, err := s.ReadFrom(buf[:])
				if err != nil {
					return
				}
				select {
				case delivered <- simulatedDatagram{bytes.Clone(buf[:n]), from.(*net.UDPAddr).AddrPort()}:
				case <-s.stopped:
					return
				}
			}
		}()
		t.Cleanup(func() { _ = s.Close(); <-done })
		return s, delivered
	}
	a, _ := start(client, Dialer)
	b, input := start(gateway, Publisher)
	for _, s := range []*Socket{a, b} {
		if err := s.WaitReady(ctx); err != nil {
			t.Fatal(err)
		}
	}
	check := func(want netip.AddrPort) {
		t.Helper()
		wantData := bytes.Repeat([]byte{42}, 128)
		if _, err := a.WriteTo(wantData, nil); err != nil {
			t.Fatal(err)
		}
		select {
		case got := <-input:
			if got.from != want || !bytes.Equal(got.data, wantData) {
				t.Fatalf("payload received from %v, want %v", got.from, want)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	check(client.local)
	if hairpin {
		return
	}
	network.hairpin.Store(true)
	network.lan.Store(false)
	for {
		a.mu.Lock()
		ready := a.ready && a.lan.peer.Load() == nil
		a.mu.Unlock()
		if ready {
			break
		}
		select {
		case <-time.After(25 * time.Millisecond):
		case <-ctx.Done():
			t.Fatal("public path did not take over after the LAN path expired")
		}
	}
	check(client.public)
}
