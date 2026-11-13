package peerrendezvous

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
)

const (
	cookiePeriod = 5 * time.Second
	peerTTL      = 20 * time.Second
	kickDuration = 30 * time.Second
)

type Coordinator struct {
	socket     net.PacketConn
	cookieKey  [32]byte
	mu         sync.Mutex
	pairs      map[[16]byte]*pair
	blockedIDs []string
	byEndpoint map[netip.AddrPort][16]byte
	data       func(p []byte, from netip.AddrPort) bool
	// publisherFor, when set, rewrites the publisher endpoint a dialer at
	// from is told. A hub uses it to answer in the dialer's IP family.
	publisherFor func(from, registered netip.AddrPort) netip.AddrPort
	done         chan struct{}
	closeOnce    sync.Once
}

type pair struct {
	key       [32]byte
	peers     [2]registration
	blocked   bool
	kickUntil time.Time
}

type registration struct {
	endpoint netip.AddrPort
	local    netip.AddrPort
	expires  time.Time
}

// Serve takes ownership of the UDP listener. The configured pairs bound
// state, and every registration proves UDP return reachability.
func Serve(socket net.PacketConn, keys [][32]byte, blockedIDs ...string) *Coordinator {
	c := newCoordinator(socket, keys, blockedIDs)
	go c.run()
	return c
}

func newCoordinator(socket net.PacketConn, keys [][32]byte, blockedIDs []string) *Coordinator {
	c := &Coordinator{
		socket: socket, pairs: make(map[[16]byte]*pair, len(keys)),
		byEndpoint: make(map[netip.AddrPort][16]byte), done: make(chan struct{}),
	}
	rand.Read(c.cookieKey[:])
	for _, key := range keys {
		c.pairs[pairID(key)] = &pair{key: key}
	}
	c.SetBlocked(blockedIDs)
	return c
}

func (*Coordinator) Interface() string { return "peer-discovery" }
func (c *Coordinator) Close() error {
	c.closeOnce.Do(func() { _ = c.socket.Close() })
	<-c.done
	return nil
}

func (c *Coordinator) run() {
	defer close(c.done)
	buf := make([]byte, 2048) // hub data packets are up to a UDP datagram of WireGuard traffic
	for {
		n, addr, err := c.socket.ReadFrom(buf[:])
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				log.Warn("peer discovery listener stopped", "err", err)
			}
			return
		}
		source, ok := addr.(*net.UDPAddr)
		if !ok {
			continue
		}
		ap := source.AddrPort()
		endpoint := netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
		if c.data != nil && (n != messageSize || string(buf[:4]) != magic) {
			if c.data(buf[:n], endpoint) {
				continue
			}
		}
		m := message(buf[:messageSize])
		if c.handle(&m, n, endpoint, time.Now()) {
			_, _ = c.socket.WriteTo(m[:], addr)
		}
	}
}

func (c *Coordinator) handle(m *message, n int, from netip.AddrPort, now time.Time) bool {
	if !m.headerOK(n) || (m.kind() != hello && m.kind() != confirm) {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	p := c.pairs[m.id()]
	if p == nil || !m.valid(p.key) {
		return false
	}
	if m.localPath() {
		return p.exchangeLocal(m, from, now)
	}
	bucket := now.Unix() / int64(cookiePeriod/time.Second)
	cookie := c.cookie(m, from, bucket)
	if m.kind() == hello {
		m[4] = challenge
		copy(m.body(), cookie[:])
	} else {
		if !hmac.Equal(m.body(), cookie[:]) {
			previous := c.cookie(m, from, bucket-1)
			if !hmac.Equal(m.body(), previous[:]) {
				return false
			}
		}
		if p.blocked || now.Before(p.kickUntil) {
			m[4] = denied
			clear(m.body())
			m.body()[0] = kicked
			if p.blocked {
				m.body()[0] = blocked
			}
			m.sign(p.key)
			return true
		}
		role := m.role()
		if !m.lookup() {
			current := &p.peers[role]
			if current.onlineEndpoint(now) != from {
				current.local = netip.AddrPort{}
			}
			if role == Dialer && current.endpoint != from {
				if c.byEndpoint == nil {
					c.byEndpoint = make(map[netip.AddrPort][16]byte)
				}
				delete(c.byEndpoint, current.endpoint)
				c.byEndpoint[from] = m.id()
			}
			current.endpoint, current.expires = from, now.Add(peerTTL)
		}
		peer := p.peers[1-role]
		endpoint := peer.onlineEndpoint(now)
		if endpoint.IsValid() && role == Dialer && c.publisherFor != nil {
			endpoint = c.publisherFor(from, endpoint)
		}
		m[4] = discovered
		m.setEndpoint(endpoint)
		// Peers sharing an external address are likely to benefit from a
		// brief LAN probe window. Older peers ignore this reserved byte.
		if endpoint.IsValid() && endpoint.Addr() == from.Addr() {
			m.body()[18] = 1
		}
	}
	m.sign(p.key)
	return true
}

// The ordinary cookie exchange has already verified reachability at from.
// LAN advertisements cannot create registrations or extend their leases.
func (p *pair) exchangeLocal(m *message, from netip.AddrPort, now time.Time) bool {
	if m.kind() != hello || p.blocked || now.Before(p.kickUntil) {
		return false
	}
	current := &p.peers[m.role()]
	if current.onlineEndpoint(now) != from {
		return false
	}
	local := m.endpoint()
	if !local.Addr().IsPrivate() || local.Addr().BitLen() != from.Addr().BitLen() {
		return false
	}
	current.local = local
	other := p.peers[1-m.role()]
	m[4] = discovered
	if other.onlineEndpoint(now).IsValid() {
		m.setEndpoint(other.local)
	} else {
		m.setEndpoint(netip.AddrPort{})
	}
	m.sign(p.key)
	return true
}

func (c *Coordinator) cookie(m *message, from netip.AddrPort, bucket int64) [24]byte {
	mac := hmac.New(sha256.New, c.cookieKey[:])
	mac.Write(m[5:40])
	ip := from.Addr().As16()
	mac.Write(ip[:])
	var binding [10]byte
	binary.BigEndian.PutUint16(binding[:2], from.Port())
	binary.BigEndian.PutUint64(binding[2:], uint64(bucket))
	mac.Write(binding[:])
	var sum [sha256.Size]byte
	mac.Sum(sum[:0])
	return [24]byte(sum[:24])
}

func (r registration) onlineEndpoint(now time.Time) netip.AddrPort {
	if !now.Before(r.expires) {
		return netip.AddrPort{}
	}
	return r.endpoint
}

type PairStatus struct {
	KickUntil time.Time
	Dialer    netip.AddrPort
	Publisher netip.AddrPort
}

func (c *Coordinator) Pairs() map[string]PairStatus {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make(map[string]PairStatus, len(c.pairs))
	for id, p := range c.pairs {
		state := PairStatus{Dialer: p.peers[Dialer].onlineEndpoint(now), Publisher: p.peers[Publisher].onlineEndpoint(now)}
		if now.Before(p.kickUntil) {
			state.KickUntil = p.kickUntil
		}
		result[hex.EncodeToString(id[:])] = state
	}
	return result
}

func (c *Coordinator) Kick(id [16]byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	p := c.pairs[id]
	if p == nil {
		return errors.New("peer discovery pairing does not exist")
	}
	if p.blocked {
		return errors.New("peer discovery pairing is blocked")
	}
	p.peers = [2]registration{}
	p.kickUntil = time.Now().Add(kickDuration)
	return nil
}

func (c *Coordinator) SetBlocked(ids []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.blockedIDs = slices.Clone(ids)
	for id, p := range c.pairs {
		block := slices.Contains(ids, hex.EncodeToString(id[:]))
		if block && !p.blocked {
			p.peers = [2]registration{}
			p.kickUntil = time.Time{}
		}
		p.blocked = block
	}
}

// AddPair registers another pairing at runtime. An existing pairing is kept.
func (c *Coordinator) AddPair(key [32]byte) {
	id := pairID(key)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pairs[id] == nil {
		c.pairs[id] = &pair{key: key, blocked: slices.Contains(c.blockedIDs, hex.EncodeToString(id[:]))}
	}
}

// RemovePair forgets a pairing at once. Its peers can no longer register or
// receive data.
func (c *Coordinator) RemovePair(key [32]byte) {
	id := pairID(key)
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.pairs, id)
	for endpoint, owner := range c.byEndpoint {
		if owner == id {
			delete(c.byEndpoint, endpoint)
		}
	}
}

// dialerOwner returns the pairing whose dialer is registered at from.
func (c *Coordinator) dialerOwner(from netip.AddrPort, now time.Time) ([16]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	id, ok := c.byEndpoint[from]
	if !ok {
		return id, false
	}
	p := c.pairs[id]
	if p == nil || p.blocked || now.Before(p.kickUntil) || p.peers[Dialer].onlineEndpoint(now) != from {
		return id, false
	}
	return id, true
}
