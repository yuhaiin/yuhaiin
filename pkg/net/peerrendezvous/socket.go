package peerrendezvous

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netstate"
)

// A restarted coordinator briefly reports an empty registration for a peer
// that is still online. Keep the direct path until the absence repeats.
const offlineAfter = 3

// Socket uses the same UDP mapping for rendezvous, hole punches and WireGuard.
// Its data-plane writes can only go to the discovered peer.
type Socket struct {
	net.PacketConn
	coordinator netip.AddrPort
	key         [32]byte
	role        Role
	id          [16]byte
	stale       func(answered bool, peer netip.Addr)
	peer        atomic.Pointer[net.UDPAddr]
	done        chan struct{}
	stopped     chan struct{}
	closeOnce   sync.Once

	mu         sync.Mutex
	nonce      [16]byte
	pending    bool
	changed    chan struct{}
	ready      bool
	leaseUntil time.Time
	denial     string
	missing    int
	answered   bool
	lastReply  time.Time
	nextStale  time.Time
	mismatch   netip.Addr
}

// NewSocket takes ownership of pc. The optional stale callback runs on its own
// goroutine, at most once per peerTTL, when this socket cannot serve the pair:
// the coordinator has been silent for peerTTL (answered tells whether it ever
// replied here), or the peer registered from the other IP family (peer is its
// address). The owner decides whether to replace the socket.
func NewSocket(pc net.PacketConn, coordinator netip.AddrPort, key [32]byte, role Role, stale func(answered bool, peer netip.Addr)) *Socket {
	s := &Socket{
		PacketConn: pc, coordinator: coordinator, key: key, role: role, id: pairID(key),
		stale:   stale,
		changed: make(chan struct{}), done: make(chan struct{}), stopped: make(chan struct{}),
		lastReply: time.Now(),
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
	for {
		s.mu.Lock()
		ready, denial, changed := s.ready, s.denial, s.changed
		s.mu.Unlock()
		select {
		case <-s.stopped:
			return net.ErrClosed
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if denial != "" {
			return errors.New("peer pairing is " + denial)
		}
		if ready {
			return nil
		}
		select {
		case <-s.stopped:
			return net.ErrClosed
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
	}
}

// Called with mu held. A new endpoint needs a new successful hole punch.
func (s *Socket) setPeer(peer *net.UDPAddr) {
	s.peer.Store(peer)
	s.ready = false
	s.signalChange()
}

func (s *Socket) signalChange() {
	close(s.changed)
	s.changed = make(chan struct{})
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
		s.nonce, s.pending = m.nonce(), true
		now := time.Now()
		if s.peer.Load() != nil && !now.Before(s.leaseUntil) {
			s.setPeer(nil)
		}
		silent := now.Sub(s.lastReply) >= peerTTL
		notify := s.stale != nil && !now.Before(s.nextStale) && (silent || s.mismatch.IsValid())
		answered, mismatch := true, s.mismatch
		if notify {
			s.nextStale = now.Add(peerTTL)
			if silent {
				answered, mismatch = s.answered, netip.Addr{}
			}
		}
		s.mu.Unlock()
		if notify {
			go s.stale(answered, mismatch)
		}
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
			s.mu.Lock()
			if !s.ready && s.peer.Load() == peer {
				s.ready = true
				s.signalChange()
			}
			s.mu.Unlock()
			continue
		}
		if n >= 32 {
			return n, addr, nil
		}
	}
}

func (s *Socket) receiveControl(m message, addr net.Addr) {
	if !m.headerOK(messageSize) || m.lookup() || m.role() != s.role || m.id() != s.id || !m.valid(s.key) {
		return
	}
	// Only an exchange this socket started may be answered. pending also
	// rejects a reply that repeats the nonce of a finished exchange.
	s.mu.Lock()
	matches := s.pending && m.nonce() == s.nonce
	if matches {
		s.answered, s.lastReply = true, time.Now()
	}
	s.mu.Unlock()
	if !matches {
		return
	}
	switch m.kind() {
	case challenge:
		m[4] = confirm
		m.sign(s.key)
		_, _ = s.PacketConn.WriteTo(m[:], addr)
	case denied:
		s.mu.Lock()
		if !s.pending || m.nonce() != s.nonce {
			s.mu.Unlock()
			return
		}
		s.pending = false
		s.missing, s.mismatch = 0, netip.Addr{}
		if s.denial != m.denial() || s.peer.Load() != nil {
			s.denial = m.denial()
			s.setPeer(nil)
		}
		s.mu.Unlock()
	case discovered:
		s.mu.Lock()
		if !s.pending || m.nonce() != s.nonce {
			s.mu.Unlock()
			return
		}
		s.pending = false
		s.leaseUntil = time.Now().Add(peerTTL)
		if s.denial != "" {
			s.denial = ""
			s.signalChange()
		}
		endpoint := m.endpoint()
		sameFamily := endpoint.Addr().BitLen() == s.coordinator.Addr().BitLen()
		s.mismatch = netip.Addr{}
		if endpoint.IsValid() && !sameFamily {
			s.mismatch = endpoint.Addr()
		}
		changed := false
		if endpoint.IsValid() && endpoint != s.coordinator && sameFamily {
			s.missing = 0
			if old := s.peer.Load(); old == nil || old.AddrPort() != endpoint {
				s.setPeer(net.UDPAddrFromAddrPort(endpoint))
				changed = true
			}
		} else if s.missing++; s.missing >= offlineAfter && s.peer.Load() != nil {
			// The peer has no usable registration. Fail new flows at
			// WaitReady instead of sending them to a dead endpoint.
			s.setPeer(nil)
		}
		s.mu.Unlock()
		if changed {
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
