package peerrendezvous

import (
	"crypto/rand"
	"net"
	"net/netip"
	"sync/atomic"
	"time"
)

const (
	localHeadStart = 150 * time.Millisecond
	localPathTTL   = 6 * time.Second
)

type localPath struct {
	prefix  netip.Prefix
	address netip.AddrPort
	peer    atomic.Pointer[net.UDPAddr]
	grace   atomic.Int64

	// Protected by the owning socket's mutex.
	advertisement [16]byte
	candidate     netip.AddrPort
	probe         [16]byte
	probePending  bool
	expires       time.Time
}

func (p *localPath) publicDelay() time.Duration {
	if until := p.grace.Load(); until != 0 {
		delay := time.Duration(until - time.Now().UnixNano())
		if delay > 0 {
			return delay
		}
		p.grace.CompareAndSwap(until, 0)
	}
	return 0
}

func (p *localPath) reset() {
	p.peer.Store(nil)
	p.grace.Store(0)
	p.advertisement = [16]byte{}
	p.candidate = netip.AddrPort{}
	p.probePending = false
	p.expires = time.Time{}
}

func (p *localPath) reachableCandidate(addr netip.AddrPort) bool {
	return addr.Port() != 0 && addr != p.address && p.prefix.Contains(addr.Addr()) && addr.Addr().IsPrivate()
}

func (s *Socket) dataPeer() *net.UDPAddr {
	if s.lan != nil {
		if peer := s.lan.peer.Load(); peer != nil {
			return peer
		}
		if s.lan.publicDelay() > 0 {
			return nil
		}
	}
	return s.peer.Load()
}

func (s *Socket) localMessage(kind byte) message {
	var m message
	copy(m[:4], magic)
	m[4], m[5], m[6] = kind, byte(s.role), localFlag
	copy(m[8:24], s.id[:])
	return m
}

func (s *Socket) advertiseLocal(coordinator net.Addr) {
	m := s.localMessage(hello)
	rand.Read(m[24:40])
	m.setEndpoint(s.lan.address)
	m.sign(s.key)
	s.mu.Lock()
	s.lan.advertisement = m.nonce()
	s.mu.Unlock()
	_, _ = s.PacketConn.WriteTo(m[:], coordinator)
}

func (s *Socket) receiveLocalCandidate(m message) {
	if s.lan == nil || !m.headerOK(messageSize) || m.kind() != discovered ||
		m.role() != s.role || m.id() != s.id || !m.valid(s.key) {
		return
	}
	addr := m.endpoint()
	s.mu.Lock()
	if m.nonce() != s.lan.advertisement || s.lan.advertisement == [16]byte{} ||
		s.peer.Load() == nil || !time.Now().Before(s.leaseUntil) {
		s.mu.Unlock()
		return
	}
	s.lan.advertisement = [16]byte{}
	if !s.lan.reachableCandidate(addr) || addr == s.coordinator {
		s.mu.Unlock()
		return
	}
	probe := s.localProbe(addr)
	s.mu.Unlock()
	_, _ = s.PacketConn.WriteTo(probe[:], net.UDPAddrFromAddrPort(addr))
}

// localProbe starts a round trip for a candidate. The caller holds s.mu.
func (s *Socket) localProbe(candidate netip.AddrPort) message {
	p := s.lan
	if p.candidate != candidate {
		p.peer.Store(nil)
		p.candidate = candidate
		s.signalChange()
	}
	m := s.localMessage(localProbe)
	rand.Read(m[24:40])
	p.probe, p.probePending = m.nonce(), true
	m.sign(s.key)
	return m
}

func (s *Socket) receiveLocalProbe(m message, from netip.AddrPort) {
	if !m.headerOK(messageSize) || m.role() != 1-s.role || m.id() != s.id ||
		!s.lan.reachableCandidate(from) || !m.valid(s.key) {
		return
	}
	s.mu.Lock()
	p := s.lan
	now := time.Now()
	if s.peer.Load() == nil || !now.Before(s.leaseUntil) || (p.candidate.IsValid() && from != p.candidate) {
		s.mu.Unlock()
		return
	}
	switch m.kind() {
	case localProbe:
		// An authenticated on-link probe may arrive before the coordinator
		// response. Probe back to verify the reverse direction independently.
		var probe *message
		if !p.probePending && p.peer.Load() == nil {
			probe = new(s.localProbe(from))
		}
		s.mu.Unlock()
		m[4], m[5] = localReply, byte(s.role)
		m.sign(s.key)
		addr := net.UDPAddrFromAddrPort(from)
		_, _ = s.PacketConn.WriteTo(m[:], addr)
		if probe != nil {
			_, _ = s.PacketConn.WriteTo(probe[:], addr)
		}
	case localReply:
		if !p.probePending || m.nonce() != p.probe {
			s.mu.Unlock()
			return
		}
		p.probePending = false
		p.expires = now.Add(localPathTTL)
		changed := p.peer.Load() == nil
		if changed {
			p.peer.Store(net.UDPAddrFromAddrPort(from))
			s.signalChange()
		}
		s.mu.Unlock()
		if changed && s.exchange != nil {
			s.exchange.request(s)
		}
	default:
		s.mu.Unlock()
	}
}
