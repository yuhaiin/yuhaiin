package toy

// An established session, and the dataplane.Tunnel it presents.
//
// This is the file worth reading if you are adding a protocol. Everything a
// veepin data path needs is here and it is not much: seal a packet, open a
// packet, say which inner destinations you carry, and say where to send. The
// pump does the rest — reading the TUN, matching outbound packets to a tunnel
// by longest prefix, and handing inbound packets to the tunnel their demux key
// names.

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xen0bit/veepin/internal/replay"
)

// replayWindowSize is how far behind the highest counter a late packet is still
// accepted. UDP reorders, so a strictly-increasing check would drop real
// traffic; 64 is generous for a toy and fits in one word.
const replayWindowSize = 64

var (
	// ErrBadTag reports a packet whose tag did not verify.
	ErrBadTag = errors.New("toy: packet tag does not verify")
	// ErrReplay reports a counter already seen, or too old to judge.
	ErrReplay = errors.New("toy: message counter replayed or outside the window")
	// ErrCounterExhausted reports a session that has sent 2^32 packets.
	ErrCounterExhausted = errors.New("toy: message counter exhausted; the session must be rebuilt")
)

// Session is one established TOY tunnel, from either role's point of view.
type Session struct {
	// ID is the server-assigned session, and the demux key.
	ID uint16
	// Key is the derived session key.
	Key Key
	// User is the authenticated name, on the server side.
	User string
	// established is when the handshake completed. Idle expiry falls back to it
	// for a session that has not yet carried a packet, so a client that
	// authenticates and then goes silent is still reaped.
	established time.Time

	// routes are the inner destinations this tunnel carries: 0.0.0.0/0 on a
	// client (everything leaving the TUN goes to the one server), and the
	// client's assigned /32 on a server.
	routes []netip.Prefix

	// counter is the next outbound message counter. It starts at 0 and is
	// pre-incremented, so the first packet sent is 1, matching the spec.
	counter atomic.Uint32

	// lastSeen is when a packet last authenticated on this session, as Unix
	// nanoseconds. It lives here rather than in the server's bookkeeping so it
	// is updated by the one function that can actually vouch for liveness --
	// open, after the tag verifies -- no matter which loop delivered the packet.
	lastSeen atomic.Int64

	mu sync.Mutex
	// peer is where to send. It is mutable because a client behind NAT can
	// change address, and the session survives that.
	peer *net.UDPAddr
	// window is the anti-replay check. It lives in internal/replay because this
	// and nebula had byte-for-byte the same one, written twice.
	window *replay.Window
}

// NewSession builds a session around a derived key.
func NewSession(id uint16, key Key, peer *net.UDPAddr, routes []netip.Prefix) *Session {
	return &Session{
		ID: id, Key: key, peer: peer, routes: routes,
		established: time.Now(),
		// A toy protocol does not need ESP-sized reordering tolerance.
		window: replay.NewSize(replayWindowSize),
	}
}

// InboundKey is the demux key: the session ID, widened. Implements
// dataplane.Tunnel.
func (s *Session) InboundKey() uint32 { return uint32(s.ID) }

// Routes are the inner destinations this tunnel carries. Implements
// dataplane.Tunnel.
func (s *Session) Routes() []netip.Prefix { return s.routes }

// PeerAddr is where encapsulated packets go. Implements dataplane.Tunnel.
func (s *Session) PeerAddr() *net.UDPAddr {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peer
}

// SetPeerAddr updates where the peer is reachable.
//
// Callers must only do this after a packet has authenticated, so the new
// address is attested by the key rather than merely claimed. Taking it from an
// unverified packet would let anyone redirect a session by spoofing one
// datagram.
func (s *Session) SetPeerAddr(addr *net.UDPAddr) {
	s.mu.Lock()
	s.peer = addr
	s.mu.Unlock()
}

// Encapsulate seals an inner IP packet as a DATA datagram. Implements
// dataplane.Tunnel.
func (s *Session) Encapsulate(inner []byte) ([]byte, error) {
	return s.seal(MsgData, inner)
}

// Decapsulate opens a DATA datagram. Implements dataplane.Tunnel.
//
// The pump hands it whole datagrams, header included, because the header is
// what the tag covers.
func (s *Session) Decapsulate(pkt []byte) ([]byte, error) {
	h, body, err := ParseHeader(pkt)
	if err != nil {
		return nil, err
	}
	if h.Type != MsgData {
		return nil, ErrMalformed
	}
	return s.open(pkt[:HeaderLen], h, body)
}

// Keepalive builds a KEEPALIVE datagram: a sealed empty payload, so it exercises
// exactly the same path as data and cannot be forged any more easily.
func (s *Session) Keepalive() ([]byte, error) { return s.seal(MsgKeepalive, nil) }

// seal builds a tagged, obscured datagram of the given type.
func (s *Session) seal(typ MsgType, payload []byte) ([]byte, error) {
	counter := s.counter.Add(1)
	if counter == 0 {
		// Wrapped. The counter keys the keystream, so reusing it would repeat
		// the pad against different plaintext -- the one failure mode here bad
		// enough to stop for rather than paper over.
		return nil, ErrCounterExhausted
	}

	header := AppendHeader(nil, Header{Type: typ, Session: s.ID, Counter: counter})

	ct := make([]byte, len(payload))
	copy(ct, payload)
	Keystream(s.Key, counter, ct)

	tag := Tag(s.Key, header, ct)

	out := make([]byte, 0, HeaderLen+TagLen+len(ct))
	out = append(out, header...)
	out = append(out, tag[:]...)
	return append(out, ct...), nil
}

// open verifies and unseals a datagram body.
//
// The order is the part worth copying: verify the tag, *then* consult the replay
// window, then decrypt. Admitting an unauthenticated counter into the window
// would let anyone who can send a datagram advance it and lock the real peer
// out of its own session.
func (s *Session) open(header []byte, h Header, body []byte) ([]byte, error) {
	if len(body) < TagLen {
		return nil, ErrShort
	}
	tag, ct := body[:TagLen], body[TagLen:]

	if !CheckTag(s.Key, header, ct, tag) {
		return nil, ErrBadTag
	}

	s.mu.Lock()
	ok := s.window.Accept(uint64(h.Counter))
	s.mu.Unlock()
	if !ok {
		return nil, ErrReplay
	}

	s.lastSeen.Store(time.Now().UnixNano())

	out := make([]byte, len(ct))
	copy(out, ct)
	Keystream(s.Key, h.Counter, out)
	return out, nil
}

// LastSeen is when a packet last authenticated on this session. The zero time
// means nothing has yet.
func (s *Session) LastSeen() time.Time {
	ns := s.lastSeen.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

// OpenAny verifies and unseals a datagram of either sealed type, reporting which
// it was. The server's read loop uses it, since a client's DATA and KEEPALIVE
// arrive on the same socket.
func (s *Session) OpenAny(pkt []byte) (MsgType, []byte, error) {
	h, body, err := ParseHeader(pkt)
	if err != nil {
		return 0, nil, err
	}
	if h.Type != MsgData && h.Type != MsgKeepalive {
		return 0, nil, ErrMalformed
	}
	inner, err := s.open(pkt[:HeaderLen], h, body)
	return h.Type, inner, err
}
