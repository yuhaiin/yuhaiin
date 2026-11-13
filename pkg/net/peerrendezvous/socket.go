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
	exchange    *LinkExchange
	lan         *localPath
	// hosted is set when the coordinator and the publisher share one socket,
	// as in a LAN Link gateway: data then arrives from the coordinator address.
	hosted atomic.Bool
	// dualStack is set when the socket reaches peers of either IP family,
	// whatever the coordinator's family, as a LAN Link gateway's does.
	dualStack atomic.Bool
	peer      atomic.Pointer[net.UDPAddr]
	done      chan struct{}
	stopped   chan struct{}
	closeOnce sync.Once

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
	return NewManagedSocket(pc, coordinator, key, role, stale, nil, netip.Prefix{})
}

func NewManagedSocket(pc net.PacketConn, coordinator netip.AddrPort, key [32]byte, role Role, stale func(answered bool, peer netip.Addr), exchange *LinkExchange, local netip.Prefix) *Socket {
	s := &Socket{
		PacketConn: pc, coordinator: coordinator, key: key, role: role, id: pairID(key),
		stale:    stale,
		exchange: exchange,
		changed:  make(chan struct{}), done: make(chan struct{}), stopped: make(chan struct{}),
		lastReply: time.Now(),
	}
	if addr, ok := pc.LocalAddr().(*net.UDPAddr); ok && local.Addr().IsPrivate() &&
		local.Addr().BitLen() == coordinator.Addr().BitLen() && addr.Port != 0 {
		s.lan = &localPath{prefix: local, address: netip.AddrPortFrom(local.Addr(), uint16(addr.Port))}
	}
	go s.run()
	return s
}

// SetHosted declares that the coordinator also serves as the peer's publisher.
func (s *Socket) SetHosted() { s.hosted.Store(true) }

// SetDualStack declares that the socket can reach peers of either IP family.
func (s *Socket) SetDualStack() { s.dualStack.Store(true) }

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
		var delay time.Duration
		if s.lan != nil {
			if s.lan.peer.Load() != nil {
				ready = true
			} else {
				delay = s.lan.publicDelay()
			}
		}
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
		var grace <-chan time.Time
		if ready {
			if delay <= 0 {
				return nil
			}
			grace = time.After(delay)
		}
		select {
		case <-s.stopped:
			return net.ErrClosed
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		case <-grace:
		}
	}
}

// Called with mu held. A new endpoint needs a new successful hole punch.
func (s *Socket) setPeer(peer *net.UDPAddr) {
	s.peer.Store(peer)
	if s.lan != nil {
		s.lan.reset()
	}
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
		if s.lan != nil && s.lan.peer.Load() != nil && !now.Before(s.lan.expires) {
			s.lan.peer.Store(nil)
			s.signalChange()
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
		if s.exchange != nil {
			s.exchange.request(s)
		}
		select {
		case <-s.stopped:
			return
		case <-ticker.C:
		}
	}
}

func (s *Socket) punch() {
	if s.lan != nil && s.lan.publicDelay() > 0 {
		return
	}
	select {
	case <-s.stopped:
		return
	default:
	}
	if peer := s.peer.Load(); peer != nil {
		_, _ = s.PacketConn.WriteTo([]byte{0}, peer)
	}
}

func (s *Socket) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := s.readPacket(p)
		if n != 0 || err != nil {
			return n, addr, err
		}
	}
}

// ReadControl pumps the socket during provisioning, before WireGuard owns the
// receive loop. Unauthenticated data packets are discarded.
func (s *Socket) ReadControl(p []byte) error {
	_, _, err := s.readPacket(p)
	return err
}

func (s *Socket) readPacket(p []byte) (int, net.Addr, error) {
	n, addr, err := s.PacketConn.ReadFrom(p)
	if err != nil {
		return 0, nil, err
	}
	source, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, nil, nil
	}
	ap := source.AddrPort()
	from := netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	if from == s.coordinator {
		if n == messageSize && string(p[:4]) == magic {
			s.receiveControl(message(p[:messageSize]), addr)
			return 0, nil, nil
		}
		if !s.hosted.Load() {
			return 0, nil, nil
		}
	}
	if s.lan != nil && n == messageSize && string(p[:4]) == magic && p[6] == localFlag {
		s.receiveLocalProbe(message(p[:messageSize]), from)
		return 0, nil, nil
	}
	public := s.peer.Load()
	if public == nil {
		return 0, nil, nil
	}
	isPublic := from == public.AddrPort()
	if !isPublic {
		if s.lan == nil {
			return 0, nil, nil
		}
		peer := s.lan.peer.Load()
		if peer == nil || from != peer.AddrPort() {
			return 0, nil, nil
		}
	}
	if isPublic && n == 1 && p[0] <= 1 {
		if p[0] == 0 {
			_, _ = s.PacketConn.WriteTo([]byte{1}, source)
		}
		s.mu.Lock()
		if !s.ready && s.peer.Load() == public {
			s.ready = true
			s.signalChange()
		}
		s.mu.Unlock()
		return 0, nil, nil
	}
	if s.exchange != nil && s.exchange.receive(s, p[:n], source) {
		return 0, nil, nil
	}
	if n >= 32 {
		return n, addr, nil
	}
	return 0, nil, nil
}

func (s *Socket) receiveControl(m message, addr net.Addr) {
	if m.localPath() {
		s.receiveLocalCandidate(m)
		return
	}
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
		sameFamily := endpoint.Addr().BitLen() == s.coordinator.Addr().BitLen() || s.dualStack.Load()
		s.mismatch = netip.Addr{}
		if endpoint.IsValid() && !sameFamily {
			s.mismatch = endpoint.Addr()
		}
		changed, preferLocal := false, false
		if endpoint.IsValid() && (endpoint != s.coordinator || s.hosted.Load()) && sameFamily {
			s.missing = 0
			if old := s.peer.Load(); old == nil || old.AddrPort() != endpoint {
				s.setPeer(net.UDPAddrFromAddrPort(endpoint))
				preferLocal = s.lan != nil && m.body()[18] == 1
				if preferLocal {
					s.lan.grace.Store(time.Now().Add(localHeadStart).UnixNano())
				}
				changed = true
			}
		} else if s.missing++; s.missing >= offlineAfter && s.peer.Load() != nil {
			// The peer has no usable registration. Fail new flows at
			// WaitReady instead of sending them to a dead endpoint.
			s.setPeer(nil)
		}
		s.mu.Unlock()
		if s.lan != nil && endpoint.IsValid() && sameFamily && endpoint != s.coordinator {
			s.advertiseLocal(addr)
		}
		if preferLocal {
			time.AfterFunc(localHeadStart, s.punch)
		} else if changed {
			s.punch()
		}
	}
}

func (s *Socket) WriteTo(p []byte, _ net.Addr) (int, error) {
	peer := s.dataPeer()
	if peer == nil {
		// WireGuard retransmits handshakes while rendezvous is in progress.
		return len(p), nil
	}
	return s.PacketConn.WriteTo(p, peer)
}
