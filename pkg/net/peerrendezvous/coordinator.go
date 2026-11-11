package peerrendezvous

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
)

const (
	cookiePeriod = 5 * time.Second
	peerTTL      = 20 * time.Second
)

type Coordinator struct {
	socket    net.PacketConn
	cookieKey [32]byte
	pairs     map[[16]byte]*pair
	done      chan struct{}
	closeOnce sync.Once
}

type pair struct {
	key   [32]byte
	peers [2]registration
}

type registration struct {
	endpoint netip.AddrPort
	expires  time.Time
}

// Serve takes ownership of the UDP listener. The fixed set of configured
// tokens bounds state, and every registration proves UDP return reachability.
func Serve(socket net.PacketConn, keys [][32]byte) *Coordinator {
	c := &Coordinator{socket: socket, pairs: make(map[[16]byte]*pair, len(keys)), done: make(chan struct{})}
	rand.Read(c.cookieKey[:])
	for _, key := range keys {
		c.pairs[pairID(key)] = &pair{key: key}
	}
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
	p := c.pairs[m.id()]
	if p == nil || !m.valid(p.key) {
		return false
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
		role := m.role()
		p.peers[role] = registration{endpoint: from, expires: now.Add(peerTTL)}
		peer := p.peers[1-role]
		m[4] = discovered
		if !now.Before(peer.expires) {
			peer.endpoint = netip.AddrPort{}
		}
		m.setEndpoint(peer.endpoint)
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
