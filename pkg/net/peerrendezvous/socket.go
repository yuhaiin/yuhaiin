package peerrendezvous

import (
	"context"
	"crypto/rand"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netstate"
)

// Socket uses the same UDP mapping for rendezvous, hole punches and WireGuard.
// Its data-plane writes can only go to the discovered peer.
type Socket struct {
	net.PacketConn
	coordinator netip.AddrPort
	key         [32]byte
	role        Role
	id          [16]byte
	peer        atomic.Pointer[net.UDPAddr]
	ready       chan struct{}
	done        chan struct{}
	stopped     chan struct{}
	readyOnce   sync.Once
	closeOnce   sync.Once

	mu    sync.Mutex
	nonce [16]byte
}

func NewSocket(pc net.PacketConn, coordinator netip.AddrPort, key [32]byte, role Role) *Socket {
	s := &Socket{
		PacketConn: pc, coordinator: coordinator, key: key, role: role, id: pairID(key),
		ready: make(chan struct{}), done: make(chan struct{}), stopped: make(chan struct{}),
	}
	go s.run()
	return s
}

func (s *Socket) NetworkPath() netstate.Path {
	if p, ok := s.PacketConn.(interface{ NetworkPath() netstate.Path }); ok {
		return p.NetworkPath()
	}
	return netstate.Path{}
}

func (s *Socket) WaitReady(ctx context.Context) error {
	select {
	case <-s.stopped:
		return net.ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	case <-s.ready:
		return nil
	}
}

func (s *Socket) Close() error {
	s.closeOnce.Do(func() {
		close(s.stopped)
		_ = s.PacketConn.Close()
	})
	<-s.done
	return nil
}

func (s *Socket) run() {
	defer close(s.done)
	coord := net.UDPAddrFromAddrPort(s.coordinator)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		var m message
		copy(m[:4], magic)
		m[4], m[5] = hello, byte(s.role)
		copy(m[8:24], s.id[:])
		rand.Read(m[24:40])
		s.mu.Lock()
		s.nonce = m.nonce()
		s.mu.Unlock()
		m.sign(s.key)
		_, _ = s.PacketConn.WriteTo(m[:], coord)
		s.punch()
		select {
		case <-s.stopped:
			return
		case <-ticker.C:
		}
	}
}

func (s *Socket) punch() {
	if peer := s.peer.Load(); peer != nil {
		_, _ = s.PacketConn.WriteTo([]byte{0}, peer)
	}
}

func (s *Socket) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := s.PacketConn.ReadFrom(p)
		if err != nil {
			return 0, nil, err
		}
		source, ok := addr.(*net.UDPAddr)
		if !ok {
			continue
		}
		ap := source.AddrPort()
		from := netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
		if from == s.coordinator {
			if n == messageSize {
				s.receiveControl(message(p[:messageSize]), addr)
			}
			continue
		}
		peer := s.peer.Load()
		if peer == nil || from != peer.AddrPort() {
			continue
		}
		if n == 1 && p[0] <= 1 {
			if p[0] == 0 {
				_, _ = s.PacketConn.WriteTo([]byte{1}, peer)
			}
			s.readyOnce.Do(func() { close(s.ready) })
			continue
		}
		if n >= 32 {
			return n, addr, nil
		}
	}
}

func (s *Socket) receiveControl(m message, addr net.Addr) {
	if !m.headerOK(messageSize) || m.role() != s.role || m.id() != s.id || !m.valid(s.key) {
		return
	}
	s.mu.Lock()
	matches := m.nonce() == s.nonce
	s.mu.Unlock()
	if !matches {
		return
	}
	switch m.kind() {
	case challenge:
		m[4] = confirm
		m.sign(s.key)
		_, _ = s.PacketConn.WriteTo(m[:], addr)
	case discovered:
		endpoint := m.endpoint()
		if !endpoint.IsValid() || endpoint == s.coordinator || endpoint.Addr().BitLen() != s.coordinator.Addr().BitLen() {
			return
		}
		old := s.peer.Load()
		if old == nil || old.AddrPort() != endpoint {
			s.peer.Store(net.UDPAddrFromAddrPort(endpoint))
			s.punch()
		}
	}
}

func (s *Socket) WriteTo(p []byte, _ net.Addr) (int, error) {
	peer := s.peer.Load()
	if peer == nil {
		// WireGuard retransmits handshakes while rendezvous is in progress.
		return len(p), nil
	}
	return s.PacketConn.WriteTo(p, peer)
}
