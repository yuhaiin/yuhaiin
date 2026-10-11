package wireguard

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xen0bit/veepin/internal/wireguard/transport"
	"github.com/xen0bit/veepin/internal/wireguard/wire"
)

// Rekey timing (protocol paper §6.1). A session's keys are replaced well before
// they would be rejected, so traffic never stops: the initiator re-handshakes
// every RekeyAfterTime, and a key is refused for sending once it is older than
// rejectAfterTime.
const (
	RekeyAfterTime  = 120 * time.Second
	rejectAfterTime = 180 * time.Second
)

var (
	// errNoSession means no handshake has completed yet; the caller should start
	// one rather than send.
	errNoSession = errors.New("wireguard: no live session")
	// errSessionExpired means the current keypair is past rejectAfterTime and
	// must be replaced before more can be sent.
	errSessionExpired = errors.New("wireguard: session expired, rekey needed")
	// errUnknownIndex means a transport packet's receiver index matches neither
	// the current nor the previous keypair — a stale or stray packet.
	errUnknownIndex = errors.New("wireguard: transport packet for an unknown session")
	// errSourceNotAllowed means a decrypted packet's source is outside the peer's
	// AllowedIPs (the inbound half of cryptokey routing).
	errSourceNotAllowed = errors.New("wireguard: inner source not in peer AllowedIPs")
)

// wgTunnel is the data-path view of one peer: it encrypts with the current
// keypair and decrypts with the current or the previous one, so a rekey can swap
// keys without dropping packets still in flight under the old one. It implements
// dataplane.Tunnel.
//
// A peer's receiver index changes on every rekey, so a wgTunnel is reachable
// under more than one inbound key at once; the client and server register and
// retire those keys with the pump as the session rotates (see install).
//
// The peer address is atomic because a server's peer roams: WireGuard lets a
// client's source address change, and the pump updates it (via SetPeerAddr) from
// the source of each inbound transport packet so replies follow. A client sets
// it once and it never moves.
type wgTunnel struct {
	routes []netip.Prefix
	peer   atomic.Pointer[net.UDPAddr]

	// verifySource enables the inbound half of cryptokey routing: a decrypted
	// packet whose source is not within this peer's AllowedIPs is dropped, so one
	// peer cannot spoof another's address. A client trusts its single server for
	// everything and leaves this off.
	verifySource bool

	mu          sync.RWMutex
	current     *transport.Session
	previous    *transport.Session
	established time.Time // when current was installed
}

// newTunnel builds a wgTunnel with its first session and peer address set.
func newTunnel(sess *transport.Session, routes []netip.Prefix, peer *net.UDPAddr, verifySource bool) *wgTunnel {
	t := &wgTunnel{routes: routes, verifySource: verifySource, current: sess, established: time.Now()}
	t.peer.Store(peer)
	return t
}

// install rotates a freshly negotiated session in as current, demoting the old
// current to previous and returning the session that fell out (the old previous)
// so the caller can retire its inbound index from the pump. The previous keypair
// stays live for decryption to cover packets still in flight under it.
func (t *wgTunnel) install(sess *transport.Session) (evicted *transport.Session) {
	t.mu.Lock()
	evicted = t.previous
	t.previous = t.current
	t.current = sess
	t.established = time.Now()
	t.mu.Unlock()
	return evicted
}

func (t *wgTunnel) Routes() []netip.Prefix { return t.routes }
func (t *wgTunnel) PeerAddr() *net.UDPAddr { return t.peer.Load() }

// InboundKey is the current session's receiver index — the pump's first
// registration for this tunnel. Later indices are added with pump.AddInboundKey
// as the session rotates on rekey.
func (t *wgTunnel) InboundKey() uint32 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.current == nil {
		return 0
	}
	return t.current.LocalIndex()
}

// SetPeerAddr updates the return address, skipping the store when it is
// unchanged so the hot inbound path does not churn the atomic on every packet.
func (t *wgTunnel) SetPeerAddr(a *net.UDPAddr) {
	if cur := t.peer.Load(); cur != nil && cur.Port == a.Port && cur.IP.Equal(a.IP) {
		return
	}
	t.peer.Store(a)
}

// Encapsulate seals an outbound packet under the current keypair, refusing once
// it is past rejectAfterTime — a peer would reject a packet under a dead key, so
// dropping it here (and letting the rekey loop re-establish) is the honest thing.
func (t *wgTunnel) Encapsulate(p []byte) ([]byte, error) {
	return t.EncapsulatePadded(p, 0)
}

// EncapsulatePadded is Encapsulate with the plaintext padded out to minInner
// octets, implementing dataplane.PaddingTunnel. WireGuard needs nothing
// negotiated for this: the inner packet is delimited by its own IP header, so
// the filler is inert to any conforming receiver.
func (t *wgTunnel) EncapsulatePadded(p []byte, minInner int) ([]byte, error) {
	sess, err := t.sendSession()
	if err != nil {
		return nil, err
	}
	return sess.SealPadded(p, minInner)
}

// AppendEncapsulated is EncapsulatePadded into the pump's buffer, implementing
// dataplane.AppendTunnel.
func (t *wgTunnel) AppendEncapsulated(dst, p []byte, minInner int) ([]byte, error) {
	sess, err := t.sendSession()
	if err != nil {
		return nil, err
	}
	return sess.AppendSeal(dst, p, minInner)
}

// sendSession is the keypair outbound packets go under, refusing once it is
// past rejectAfterTime.
func (t *wgTunnel) sendSession() (*transport.Session, error) {
	t.mu.RLock()
	sess := t.current
	expired := sess != nil && time.Since(t.established) >= rejectAfterTime
	t.mu.RUnlock()
	if sess == nil {
		return nil, errNoSession
	}
	if expired {
		return nil, errSessionExpired
	}
	return sess, nil
}

// Decapsulate opens an inbound transport packet with whichever keypair its
// receiver index names — current or previous — so a rekey does not drop packets
// still arriving under the old key.
func (t *wgTunnel) Decapsulate(p []byte) ([]byte, error) {
	idx, ok := wire.Demux(p)
	if !ok {
		return nil, errUnknownIndex
	}
	t.mu.RLock()
	var sess *transport.Session
	switch {
	case t.current != nil && t.current.LocalIndex() == idx:
		sess = t.current
	case t.previous != nil && t.previous.LocalIndex() == idx:
		sess = t.previous
	}
	t.mu.RUnlock()
	if sess == nil {
		return nil, errUnknownIndex
	}
	inner, err := sess.Open(p)
	if err != nil || len(inner) == 0 {
		return inner, err // error, or a keepalive the pump will drop
	}
	if t.verifySource && !t.sourceAllowed(inner) {
		return nil, errSourceNotAllowed
	}
	return inner, nil
}

// sourceAllowed reports whether an inbound inner packet's source address falls
// within this peer's routes — the inbound direction of cryptokey routing.
//
// Both families, because AllowedIPs accepts both. It used to read the IPv4
// header only and return false for anything else, which is the
// accepted-and-ignored shape: `AllowedIPs = fd00::/8` parses, is stored, is
// used to install routes, and then every inbound IPv6 packet is dropped by
// this function as though the peer had sent something it was not allowed to.
// Nothing logs it — a dropped packet on this path is indistinguishable from
// one that never arrived.
func (t *wgTunnel) sourceAllowed(inner []byte) bool {
	src, ok := innerSource(inner)
	if !ok {
		return false
	}
	for _, r := range t.routes {
		// Contains is family-aware and returns false across families, so a v4
		// route never admits a v6 source or the reverse. An IPv4-mapped v6
		// address would slip past that, which is why innerSource returns the
		// address in its own family rather than a 16-octet form.
		if r.Contains(src) {
			return true
		}
	}
	return false
}

// innerSource extracts the source address of an inner IP packet, for either
// family. It is the counterpart of dataplane.innerDest, which the outbound half
// of cryptokey routing has always used and which has always handled both.
func innerSource(pkt []byte) (netip.Addr, bool) {
	if len(pkt) < 1 {
		return netip.Addr{}, false
	}
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom4([4]byte(pkt[12:16])), true
	case 6:
		// Fixed 40-octet header; the source is octets 8..24.
		if len(pkt) < 40 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom16([16]byte(pkt[8:24])), true
	}
	return netip.Addr{}, false
}
