package wireguard

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/tailscale/wireguard-go/conn"
)

const (
	serverPeerPrefix    = "wgpeer:"
	handshakeMaxPending = 4096
	handshakePendingTTL = 15 * time.Second
)

// serverBind learns UDP endpoints from successfully authenticated WireGuard
// traffic, without relying on a host route, TUN, or a fixed client Endpoint.
// wireguard-go's custom engine does not automatically bind the endpoint of
// an incoming handshake to an existing configured peer.
type serverBind struct {
	conn.Bind
	mu      sync.Mutex
	peers   map[string]conn.Endpoint
	pending map[uint32]pendingHandshake
}

type pendingHandshake struct {
	endpoint conn.Endpoint
	seen     time.Time
}

func newServerBind(base conn.Bind) *serverBind {
	return &serverBind{Bind: base, peers: make(map[string]conn.Endpoint), pending: make(map[uint32]pendingHandshake)}
}

var _ conn.Bind = (*serverBind)(nil)
var _ conn.PeerAwareEndpoint = (*serverReceiveEndpoint)(nil)

type serverPeerEndpoint struct {
	key string
}

func (e serverPeerEndpoint) ClearSrc()           {}
func (e serverPeerEndpoint) SrcToString() string { return "" }
func (e serverPeerEndpoint) DstToString() string { return serverPeerPrefix + e.key }
func (e serverPeerEndpoint) DstToBytes() []byte  { return nil }
func (e serverPeerEndpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (e serverPeerEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

type serverReceiveEndpoint struct {
	conn.Endpoint
	owner *serverBind
}

func (e *serverReceiveEndpoint) FromPeer(key [32]byte) {
	e.owner.mu.Lock()
	e.owner.peers[hex.EncodeToString(key[:])] = e.Endpoint
	e.owner.mu.Unlock()
}

func (b *serverBind) ParseEndpoint(address string) (conn.Endpoint, error) {
	if key, ok := strings.CutPrefix(address, serverPeerPrefix); ok {
		data, err := hex.DecodeString(key)
		if err != nil || len(data) != 32 {
			return nil, errors.New("wireguard: invalid server peer endpoint")
		}
		return serverPeerEndpoint{key: key}, nil
	}
	return b.Bind.ParseEndpoint(address)
}

func (b *serverBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	receivers, actualPort, err := b.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	wrapped := make([]conn.ReceiveFunc, len(receivers))
	for i, receive := range receivers {
		wrapped[i] = func(slab []byte, packets []conn.ReceivedPacket) (int, error) {
			n, err := receive(slab, packets)
			for j := 0; j < n; j++ {
				packet := packets[j].Bytes(slab)
				original := packets[j].Endpoint
				if len(packet) >= 8 && binary.LittleEndian.Uint32(packet[:4]) == 1 {
					b.mu.Lock()
					// Pending entries are unauthenticated and therefore strictly bounded.
					// Expiry also prevents stale handshake indices accumulating forever.
					now := time.Now()
					if len(b.pending) >= handshakeMaxPending {
						for id, p := range b.pending {
							if now.Sub(p.seen) >= handshakePendingTTL {
								delete(b.pending, id)
							}
						}
						if len(b.pending) >= handshakeMaxPending {
							for id := range b.pending {
								delete(b.pending, id)
								break
							}
						}
					}
					b.pending[binary.LittleEndian.Uint32(packet[4:8])] = pendingHandshake{endpoint: original, seen: now}
					b.mu.Unlock()
				}
				packets[j].Endpoint = &serverReceiveEndpoint{Endpoint: original, owner: b}
			}
			return n, err
		}
	}
	return wrapped, actualPort, nil
}

func (b *serverBind) Send(buffers [][]byte, destination conn.Endpoint, offset int) error {
	peer, ok := destination.(serverPeerEndpoint)
	if !ok {
		return b.Bind.Send(buffers, destination, offset)
	}
	b.mu.Lock()
	real := b.peers[peer.key]
	// The server has verified the client's Noise handshake before requesting a
	// response. Its receiver index matches the index from the original request.
	for _, packet := range buffers {
		if offset >= 0 && offset <= len(packet) {
			p := packet[offset:]
			if len(p) >= 12 && binary.LittleEndian.Uint32(p[:4]) == 2 {
				id := binary.LittleEndian.Uint32(p[8:12])
				if candidate, found := b.pending[id]; found {
					if time.Since(candidate.seen) < handshakePendingTTL {
						real = candidate.endpoint
						b.peers[peer.key] = real
					}
					delete(b.pending, id)
				}
			}
		}
	}
	b.mu.Unlock()
	if real == nil {
		return fmt.Errorf("wireguard: no authenticated endpoint for peer %s", peer.key[:8])
	}
	return b.Bind.Send(buffers, real, offset)
}

func (b *serverBind) Close() error {
	b.mu.Lock()
	clear(b.peers)
	clear(b.pending)
	b.mu.Unlock()
	return b.Bind.Close()
}
