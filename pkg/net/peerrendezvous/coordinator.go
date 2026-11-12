package peerrendezvous

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"maps"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/contract/transport"
	"github.com/Asutorufa/yuhaiin/pkg/log"
)

const (
	cookiePeriod    = 5 * time.Second
	peerTTL         = 20 * time.Second
	kickDuration    = 30 * time.Second
	enrollmentTTL   = 2 * peerTTL
	maxManagedPairs = 1024
)

type Coordinator struct {
	socket       net.PacketConn
	cookieKey    [32]byte
	mu           sync.Mutex
	pairs        map[[16]byte]*pair
	authorities  map[[16]byte][32]byte
	blockedIDs   []string
	managedCount int
	done         chan struct{}
	closeOnce    sync.Once
}

type pair struct {
	key           [32]byte
	peers         [2]registration
	blocked       bool
	kickUntil     time.Time
	enrolledUntil time.Time
}

type registration struct {
	endpoint netip.AddrPort
	local    netip.AddrPort
	expires  time.Time
}

// Serve takes ownership of the UDP listener. The fixed set of configured
// tokens bounds state, and every registration proves UDP return reachability.
func Serve(socket net.PacketConn, keys [][32]byte, blockedIDs ...string) *Coordinator {
	return ServeWithAuthorities(socket, keys, nil, blockedIDs...)
}

func ServeWithAuthorities(socket net.PacketConn, keys, authorities [][32]byte, blockedIDs ...string) *Coordinator {
	c := &Coordinator{
		socket: socket, pairs: make(map[[16]byte]*pair, len(keys)),
		authorities: make(map[[16]byte][32]byte, len(authorities)), done: make(chan struct{}),
	}
	for _, authority := range authorities {
		c.authorities[pairID(authority)] = authority
	}
	rand.Read(c.cookieKey[:])
	for _, key := range keys {
		c.pairs[pairID(key)] = &pair{key: key}
	}
	c.SetBlocked(blockedIDs)
	go c.run()
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
	var buf [messageSize + 1]byte
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
	if m.enrollment() {
		return c.handleEnrollment(m, from, now)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	p := c.pairs[m.id()]
	if p == nil || (!p.enrolledUntil.IsZero() && !now.Before(p.enrolledUntil)) || !m.valid(p.key) {
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
			current.endpoint, current.expires = from, now.Add(peerTTL)
		}
		peer := p.peers[1-role]
		endpoint := peer.onlineEndpoint(now)
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

func (c *Coordinator) handleEnrollment(m *message, from netip.AddrPort, now time.Time) bool {
	authority, ok := c.authorities[m.id()]
	if !ok || !m.valid(authority) {
		return false
	}
	bucket := now.Unix() / int64(cookiePeriod/time.Second)
	cookie := c.cookie(m, from, bucket)
	if m.kind() == hello {
		m[4] = challenge
		copy(m.body(), cookie[:])
		m.sign(authority)
		return true
	}
	previous := c.cookie(m, from, bucket-1)
	if !hmac.Equal(m.body(), cookie[:]) && !hmac.Equal(m.body(), previous[:]) {
		return false
	}
	key, err := transport.LANLinkRegistrationKey(authority, m.nonce())
	if err != nil {
		return false
	}
	id := pairID(key)
	c.mu.Lock()
	defer c.mu.Unlock()
	p := c.pairs[id]
	if p == nil {
		maps.DeleteFunc(c.pairs, func(_ [16]byte, p *pair) bool {
			expired := !p.enrolledUntil.IsZero() && !now.Before(p.enrolledUntil)
			if expired {
				c.managedCount--
			}
			return expired
		})
		if c.managedCount >= maxManagedPairs {
			return false
		}
		p = &pair{key: key, blocked: slices.Contains(c.blockedIDs, hex.EncodeToString(id[:]))}
		c.pairs[id] = p
		c.managedCount++
	} else if p.enrolledUntil.IsZero() {
		return false
	}
	p.enrolledUntil = now.Add(enrollmentTTL)
	m[4] = discovered
	clear(m.body())
	m.sign(authority)
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
		if !p.enrolledUntil.IsZero() && !now.Before(p.enrolledUntil) {
			continue
		}
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
