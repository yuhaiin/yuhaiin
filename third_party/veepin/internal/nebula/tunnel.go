package nebula

// A keyed tunnel to one peer.
//
// Once the Noise handshake completes, each side holds two transport keys — one
// per direction — and a counter that serves as both the replay identifier and
// the AEAD nonce. A data packet is the 16-octet header followed by the
// ciphertext, with the header itself authenticated as additional data, so the
// type, tunnel index and counter cannot be altered in flight.
//
// Nebula reserves counters 1 and 2 for the two handshake messages, so data
// traffic begins at 3. Seeding the counter and the replay window from that
// point is what keeps the handshake's own messages from later looking like
// packets that went missing.

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xen0bit/veepin/internal/replay"
)

// handshakeMessageCount is the number of messages the IX pattern exchanges, and
// therefore the number of message counters it consumes.
const handshakeMessageCount = 2

var (
	errNotForUs    = errors.New("nebula: packet does not authenticate for this tunnel")
	errReplayed    = errors.New("nebula: message counter replayed or outside the window")
	errShortPacket = errors.New("nebula: packet is too short to hold a header and tag")
)

// tunnel is an established session with one peer.
type tunnel struct {
	// localIndex is the identifier this host chose; the peer puts it in the
	// remote index field of everything it sends here.
	localIndex uint32
	// remoteIndex is the peer's identifier, which this host echoes.
	remoteIndex uint32

	// weInitiated records which side started the handshake. Two hosts can key a
	// tunnel to each other at the same time, and resolving that collision needs
	// a rule both sides can evaluate identically -- see Host.install.
	weInitiated bool

	cipher   noiseCipher
	send     cipher.AEAD
	recv     cipher.AEAD
	peerCert *Certificate
	// peerAddr is the overlay address the peer's certificate vouches for.
	peerAddr netip.Addr

	counter atomic.Uint64

	// lastSeen is when a packet last authenticated on this tunnel, as Unix
	// nanoseconds, and established is when the handshake completed. Idle expiry
	// uses them; lastSeen is set by decrypt, which is the only place that can
	// vouch for a tunnel still being live.
	lastSeen    atomic.Int64
	established time.Time

	// probeDeadline is when an outstanding reachability probe gives up, as Unix
	// nanoseconds, or zero when none is outstanding. It is separate from
	// lastSeen because the question it answers is different: lastSeen says when
	// the peer was last heard from, and this says whether it has been asked.
	probeDeadline atomic.Int64

	mu     sync.Mutex
	window *replay.Window

	// recvNonce is scratch for the inbound nonce. decrypt runs only on the Host's
	// single readUDP goroutine, so one buffer per tunnel is reused across packets
	// without a lock and without escaping to the heap on every Open.
	recvNonce [nonceLen]byte
}

// newTunnel builds a tunnel from a completed handshake.
func newTunnel(c noiseCipher, weInitiated bool, localIndex, remoteIndex uint32, sendKey, recvKey [keySize]byte, peer *Certificate) (*tunnel, error) {
	sendAEAD, err := c.aead(sendKey[:])
	if err != nil {
		return nil, err
	}
	recvAEAD, err := c.aead(recvKey[:])
	if err != nil {
		return nil, err
	}

	addr, ok := peer.Address()
	if !ok {
		return nil, fmt.Errorf("nebula: peer certificate %q carries no overlay address", peer.Name)
	}

	t := &tunnel{
		localIndex:  localIndex,
		remoteIndex: remoteIndex,
		weInitiated: weInitiated,
		cipher:      c,
		send:        sendAEAD,
		recv:        recvAEAD,
		peerCert:    peer,
		peerAddr:    addr,
		established: time.Now(),
		window:      replay.New(),
	}
	t.counter.Store(handshakeMessageCount)
	t.window.MarkSeen(handshakeMessageCount)
	return t, nil
}

// PeerAddr returns the overlay address the peer is authorized to use.
func (t *tunnel) PeerAddr() netip.Addr { return t.peerAddr }

// encrypt wraps a payload for transmission. The header is generated here rather
// than supplied so that the counter and the nonce cannot drift apart.
func (t *tunnel) encrypt(typ messageType, sub messageSubType, payload []byte) []byte {
	counter := t.counter.Add(1)
	h := header{
		Version:        headerVersion,
		Type:           typ,
		Subtype:        sub,
		RemoteIndex:    t.remoteIndex,
		MessageCounter: counter,
	}
	// Allocate the output with room for the nonce past where Seal will write, and
	// build the nonce there. Because that scratch lives in the buffer already being
	// returned, it does not escape separately — each concurrent encrypt has its own
	// buffer, so no lock is needed either.
	sealedLen := headerLen + len(payload) + tagSize
	out := h.encode(make([]byte, 0, sealedLen+nonceLen))
	nonce := out[sealedLen : sealedLen+nonceLen]
	t.cipher.putNonce(nonce, counter)
	return t.send.Seal(out, nonce, payload, out[:headerLen])
}

// decrypt authenticates and unwraps a received packet.
//
// The order here is the security-relevant part: the packet is authenticated
// before its counter touches the replay window. Admitting an unauthenticated
// counter would let anyone who can send a datagram advance the window and lock
// the tunnel out of its own peer's traffic.
// sealRelay builds a relayed packet: the outer header, the payload in the
// clear, and an AEAD tag over both.
//
// The payload is NOT encrypted here, and that is the protocol rather than an
// oversight. A relay has to read the inner nebula header to know where to
// forward, and it holds none of the end-to-end keys -- so the hop to the relay
// authenticates the bytes without hiding them. The reference does exactly this
// in SendVia: EncryptDanger with a nil plaintext and the whole buffer as
// additional data.
//
// What the payload contains is already encrypted: it is a complete nebula
// packet for the far end, keyed under a tunnel this host and the far end share
// and the relay does not. See relay.go for what a relay can therefore learn.
// The index it stamps is the *relay* index, not the tunnel's own remote index:
// a relayed packet is demultiplexed against the receiver's relay table rather
// than its tunnel table, and the two namespaces are separate.
func (t *tunnel) sealRelayTo(relayIndex uint32, payload []byte) []byte {
	counter := t.counter.Add(1)
	h := header{
		Version:        headerVersion,
		Type:           typeMessage,
		Subtype:        subTypeRelay,
		RemoteIndex:    relayIndex,
		MessageCounter: counter,
	}

	sealedLen := headerLen + len(payload) + tagSize
	out := h.encode(make([]byte, 0, sealedLen+nonceLen))
	out = append(out, payload...)

	nonce := out[sealedLen : sealedLen+nonceLen]
	t.cipher.putNonce(nonce, counter)
	// Nil plaintext, everything so far as additional data: the tag lands after
	// the payload and covers the header and the payload together.
	return t.send.Seal(out, nonce, nil, out)
}

// openRelay verifies a relayed packet and returns the payload it carries,
// which is a whole nebula packet addressed to somewhere else.
//
// The returned slice aliases pkt.
func (t *tunnel) openRelay(pkt []byte) (header, []byte, error) {
	h, err := parseHeader(pkt)
	if err != nil {
		return header{}, nil, err
	}
	if len(pkt) < headerLen+tagSize {
		return header{}, nil, errShortPacket
	}

	signed := pkt[:len(pkt)-tagSize]
	tag := pkt[len(pkt)-tagSize:]

	t.cipher.putNonce(t.recvNonce[:], h.MessageCounter)
	if _, err := t.recv.Open(nil, t.recvNonce[:], tag, signed); err != nil {
		return header{}, nil, fmt.Errorf("%w: %w", errNotForUs, err)
	}

	t.mu.Lock()
	ok := t.window.Accept(h.MessageCounter)
	t.mu.Unlock()
	if !ok {
		return header{}, nil, errReplayed
	}

	t.lastSeen.Store(time.Now().UnixNano())
	return h, signed[headerLen:], nil
}

func (t *tunnel) decrypt(pkt []byte) (header, []byte, error) {
	h, err := parseHeader(pkt)
	if err != nil {
		return header{}, nil, err
	}
	if len(pkt) < headerLen+tagSize {
		return header{}, nil, errShortPacket
	}

	// Decrypt in place: the plaintext reuses the ciphertext's storage, and the
	// nonce comes from per-tunnel scratch (safe on the single inbound goroutine),
	// so a received packet is opened without allocating. The returned plaintext
	// aliases pkt, which readUDP owns exclusively until this returns.
	t.cipher.putNonce(t.recvNonce[:], h.MessageCounter)
	body := pkt[headerLen:]
	pt, err := t.recv.Open(body[:0], t.recvNonce[:], body, pkt[:headerLen])
	if err != nil {
		return header{}, nil, fmt.Errorf("%w: %w", errNotForUs, err)
	}

	t.mu.Lock()
	ok := t.window.Accept(h.MessageCounter)
	t.mu.Unlock()
	if !ok {
		return header{}, nil, errReplayed
	}

	t.lastSeen.Store(time.Now().UnixNano())
	return h, pt, nil
}

// awaitProbe records that a reachability probe has gone out and must be
// answered by deadline. It reports false if one is already outstanding, so a
// second probe is not sent while the first is still in flight.
func (t *tunnel) awaitProbe(deadline time.Time) bool {
	return t.probeDeadline.CompareAndSwap(0, deadline.UnixNano())
}

// probeExpired reports whether an outstanding probe has passed its deadline
// without the peer being heard from.
func (t *tunnel) probeExpired(now time.Time) bool {
	d := t.probeDeadline.Load()
	return d != 0 && now.UnixNano() > d
}

// clearProbe forgets any outstanding probe. Called when the peer is heard from
// -- by any packet, not only a test reply, since anything that authenticates on
// this tunnel answers the question a probe was asking.
func (t *tunnel) clearProbe() { t.probeDeadline.Store(0) }

// LastSeen is when a packet last authenticated on this tunnel; the zero time
// means nothing has.
func (t *tunnel) LastSeen() time.Time {
	ns := t.lastSeen.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

// newLocalIndex picks the identifier this host will be addressed by. It has to
// be unpredictable: it is the only tunnel selector a packet carries, so a
// guessable one would let an off-path attacker aim forged packets at a
// specific session.
func newLocalIndex() (uint32, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	idx := binary.BigEndian.Uint32(b[:])
	if idx == 0 {
		// Zero is how nebula spells "no index yet" in a handshake, so it is
		// not usable as a real one.
		idx = 1
	}
	return idx, nil
}
