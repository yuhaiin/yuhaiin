// Package transport is WireGuard's data path: it turns the directional keys a
// completed handshake yields into type-4 transport messages and back.
//
// It is where the handshake stops and steady-state traffic begins. A Session
// holds one keypair — a sending key and a receiving key — plus the two counters
// that keep the AEAD nonce unique: an outbound counter that increments per
// packet, and an inbound anti-replay window that rejects a nonce the peer has
// already spent.
//
// The construction is fixed (ChaCha20-Poly1305, a 64-bit counter in the nonce,
// empty additional data) and taken from the protocol paper §5.4.6. There is no
// negotiation and no state machine here; rekeying is the handshake's business,
// and a fresh handshake simply produces a fresh Session.
package transport

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/cryptoutil"
	"github.com/xen0bit/veepin/internal/wireguard/wire"
)

// RejectAfterMessages is the largest counter a Session will use or accept: a
// keypair must be replaced before the 64-bit nonce space runs out (protocol
// paper §6.1). It is 2^64 - 2^13 - 1, leaving a margin below the wrap so a
// handful of in-flight packets past the limit cannot alias counter zero.
const RejectAfterMessages uint64 = (1 << 64) - (1 << 13) - 1

var (
	// ErrDecrypt reports a transport packet that failed authentication: a wrong
	// key or a forgery. Like the handshake's, it is deliberately opaque.
	ErrDecrypt = errors.New("transport: message authentication failed")
	// ErrReplay reports a packet whose counter has already been seen or has
	// fallen behind the replay window. The packet authenticated, so this is a
	// genuine replay or a badly reordered path, not a forgery.
	ErrReplay = errors.New("transport: replayed or stale counter")
	// ErrExhausted reports that the sending counter has reached
	// RejectAfterMessages: the keypair must be replaced before more can be sent.
	ErrExhausted = errors.New("transport: sending key exhausted, rekey required")
	// ErrShort reports a packet too small to be a transport message.
	ErrShort = errors.New("transport: packet too short")
)

// Session encrypts and decrypts one peer's transport traffic under a single
// handshake's keys. It is safe for concurrent use: Seal is lock-free on an
// atomic counter, and Open serialises only the anti-replay window update.
type Session struct {
	send, recv    cipher.AEAD
	local, remote uint32

	// counter is the next outbound nonce. It only ever increases, so a plain
	// atomic add gives each packet a unique nonce without a lock.
	counter atomic.Uint64

	mu     sync.Mutex
	replay replayFilter
}

// NewSession builds a Session from a completed handshake's keying material:
// sendKey protects our outbound packets, recvKey opens the peer's, local is the
// index the peer addresses us by (and the pump demuxes on), and remote is the
// index we stamp on packets to the peer.
func NewSession(sendKey, recvKey [wire.KeySize]byte, local, remote uint32) (*Session, error) {
	send, err := cryptoutil.NewChaCha20Poly1305(sendKey[:])
	if err != nil {
		return nil, err
	}
	recv, err := cryptoutil.NewChaCha20Poly1305(recvKey[:])
	if err != nil {
		return nil, err
	}
	return &Session{send: send, recv: recv, local: local, remote: remote}, nil
}

// LocalIndex is the receiver index this session is addressed by — its
// dataplane.Tunnel inbound key.
func (s *Session) LocalIndex() uint32 { return s.local }

// RemoteIndex is the index the peer is addressed by.
func (s *Session) RemoteIndex() uint32 { return s.remote }

// nonceTail is the length of a ChaCha20-Poly1305 nonce: four zero octets
// followed by the 64-bit counter (protocol paper §5.4.6).
const nonceLen = 12

// Seal encrypts an inner IP packet into a type-4 transport message. A nil or
// empty inner packet produces a keepalive: a message with an empty payload,
// which the peer authenticates and then discards.
func (s *Session) Seal(inner []byte) ([]byte, error) {
	return s.seal(inner, 0)
}

// SealPadded is Seal with the plaintext padded out to at least minInner octets
// instead of just to the next 16-octet boundary, so the message's size on the
// wire says less about the packet inside it (dataplane.Shaper drives this).
//
// It needs no negotiation and no peer support: WireGuard's inner packet is
// delimited by its own IP header, which is exactly why Open trims by that
// header, so the extra octets are inert to any conforming receiver — the
// official clients included.
//
// A keepalive is never padded. Its emptiness is what marks it as one.
func (s *Session) SealPadded(inner []byte, minInner int) ([]byte, error) {
	return s.seal(inner, minInner)
}

// AppendSeal is SealPadded appending the message to dst rather than to a fresh
// buffer; minInner of zero means unpadded. A caller that reuses dst -- the pump,
// through dataplane.AppendTunnel -- seals without allocating. dst needs room for
// twelve octets of nonce scratch past the message as well; with less, it grows.
func (s *Session) AppendSeal(dst, inner []byte, minInner int) ([]byte, error) {
	return s.appendSeal(dst, inner, minInner)
}

func (s *Session) seal(inner []byte, minInner int) ([]byte, error) {
	// Sized exactly, so the one allocation Seal makes is the packet.
	n := wire.TransportHeaderLen + paddedLen(len(inner), minInner) + wire.TagSize + nonceLen
	return s.appendSeal(make([]byte, 0, n), inner, minInner)
}

func (s *Session) appendSeal(dst, inner []byte, minInner int) ([]byte, error) {
	// Reserve this packet's counter. Add returns the post-increment value, so
	// the first packet uses counter 0.
	counter := s.counter.Add(1) - 1
	if counter >= RejectAfterMessages {
		return nil, ErrExhausted
	}

	padded := paddedLen(len(inner), minInner)
	msgLen := wire.TransportHeaderLen + padded + wire.TagSize
	// One buffer for the whole packet: the header, the padded plaintext, the
	// tag, and a 12-octet nonce scratch at the tail. The plaintext is laid down
	// in place and sealed over itself, so padding costs no separate buffer, and
	// building the nonce in the tail keeps it from escaping through the AEAD's
	// []byte parameter — Seal needs no shared scratch and stays safe to call
	// concurrently with keepalives.
	start := len(dst)
	dst = slices.Grow(dst, msgLen+nonceLen)
	buf := dst[start : start+msgLen+nonceLen]
	out := buf[:wire.TransportHeaderLen]
	if err := wire.PutTransportHeader(out, s.remote, counter); err != nil {
		return nil, err
	}
	// Copy the inner packet into the plaintext region, and zero the rest up to
	// the 16-octet boundary -- pad's zero fill. Explicitly: a reused buffer
	// still holds whatever was last built in it, and filler is zeros by the
	// protocol's definition, not by what the buffer happened to contain.
	plaintext := buf[wire.TransportHeaderLen : wire.TransportHeaderLen+padded]
	clear(plaintext[copy(plaintext, inner):])
	nonce := buf[msgLen:]
	clear(nonce[:4])
	binary.LittleEndian.PutUint64(nonce[4:], counter)
	// Additional data is empty for transport packets; only the payload is
	// authenticated (the header's integrity does not matter — a tampered
	// counter simply decrypts to garbage under the wrong nonce and fails). Seal
	// writes the ciphertext back over the plaintext it just read (exact overlap,
	// which the AEAD permits).
	sealed := s.send.Seal(out, nonce, plaintext, nil)
	return dst[:start+len(sealed)], nil
}

// Open decrypts a type-4 transport message into its inner IP packet, checking
// the anti-replay window. It returns (nil, nil) for a keepalive — an
// authenticated message with no inner packet — which the caller must not write
// to the TUN.
//
// pkt is decrypted in place, so the caller must own the buffer (the pump passes
// a fresh copy).
func (s *Session) Open(pkt []byte) ([]byte, error) {
	if len(pkt) < wire.MinTransportData {
		return nil, ErrShort
	}
	counter, _ := wire.TransportCounter(pkt)
	if counter >= RejectAfterMessages {
		return nil, ErrReplay
	}
	// The nonce is four zero octets followed by the counter little-endian. The
	// counter already sits at pkt[8:16], and pkt[4:8] (the receiver index) has
	// done its job — the pump demuxed on it to reach this Session — so zeroing it
	// leaves pkt[4:16] as exactly that nonce, with no scratch buffer to escape.
	clear(pkt[4:8])
	nonce := pkt[4:wire.TransportHeaderLen]
	body := pkt[wire.TransportHeaderLen:]
	// Decrypt into the ciphertext's own storage: the plaintext is shorter, so it
	// fits, and this keeps the data path allocation-free.
	plain, err := s.recv.Open(body[:0], nonce, body, nil)
	if err != nil {
		return nil, ErrDecrypt
	}
	// Only advance the replay window after authentication: a forged packet must
	// never move it, or it could be used to lock out genuine traffic.
	s.mu.Lock()
	fresh := s.replay.validate(counter)
	s.mu.Unlock()
	if !fresh {
		return nil, ErrReplay
	}
	return dataplane.TrimToIP(plain), nil
}

// paddedLen rounds a plaintext length up to a 16-octet boundary, as WireGuard
// requires so that packet lengths leak less about their contents (protocol
// paper §5.4.6). minInner raises the floor first, which is how the shaper asks
// for more than alignment. An empty packet stays empty — a keepalive carries no
// padding, because being empty is what identifies it.
func paddedLen(n, minInner int) int {
	const boundary = 16
	if n == 0 {
		return 0
	}
	if minInner > n {
		// Round the *target* down to the boundary before taking it. Rounding it
		// up instead would push the packet past the size the shaper chose it
		// against — the inner MTU — and the few octets over would be paid for
		// by fragmentation of the outer datagram.
		if aligned := minInner - minInner%boundary; aligned > n {
			n = aligned
		}
	}
	rem := n % boundary
	if rem == 0 {
		return n
	}
	return n + boundary - rem
}
