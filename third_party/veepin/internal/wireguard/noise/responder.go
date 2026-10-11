package noise

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/xen0bit/veepin/internal/cryptoutil"
	"github.com/xen0bit/veepin/internal/wireguard/wire"
)

// ErrMAC1 reports an initiation whose mac1 does not authenticate to our static
// key: it was not addressed to this responder (a scan, a stray packet, or a
// misconfigured peer). It is checked before any Diffie-Hellman work, so it is
// also the cheap first line against a flood — a responder does not spend a
// curve operation on a packet that is not even aimed at it.
var ErrMAC1 = errors.New("noise: initiation not addressed to this responder")

// Responder drives one handshake from the receiving side. Unlike Initiator it is
// split into two calls, because the responder must decide *who* the peer is
// before it can answer: Consume decrypts the initiation and reveals the peer's
// static key without touching the preshared key, the caller looks that key up in
// its peer table, and Response completes the handshake with the peer's preshared
// key (or zeros).
//
// A Responder handles a single initiation. The caller makes a fresh one per
// initiation, which also keeps each response's ephemeral key single-use.
type Responder struct {
	localStatic *ecdh.PrivateKey
	mac1Key     key

	ck, h key

	peerEph    *ecdh.PublicKey
	peerStatic *ecdh.PublicKey
	peerIndex  uint32
	timestamp  [wire.TimestampLen]byte

	consumed bool

	// typeInitiation / typeResponse are AmneziaWG's H1 and H2, used only when
	// computing mac1 — see the note on noise.Config.
	typeInitiation uint32
	typeResponse   uint32
}

// NewResponder prepares to answer initiations addressed to localStatic, with
// stock message types.
func NewResponder(localStatic [KeySize]byte) (*Responder, error) {
	return NewResponderWithTypes(localStatic, 0, 0)
}

// NewResponderWithTypes is NewResponder for an AmneziaWG responder: h1 and h2
// are the substituted message-type words that mac1 is computed over. Zero for
// either means the stock constant. See the note on Config.
func NewResponderWithTypes(localStatic [KeySize]byte, h1, h2 uint32) (*Responder, error) {
	priv, err := ecdh.X25519().NewPrivateKey(localStatic[:])
	if err != nil {
		return nil, fmt.Errorf("noise: local static key: %w", err)
	}
	return &Responder{
		localStatic:    priv,
		mac1Key:        hashOf([]byte(labelMAC1), priv.PublicKey().Bytes()),
		typeInitiation: h1,
		typeResponse:   h2,
	}, nil
}

// Consume processes message type 1 (protocol paper §5.4.2) from the responder's
// side. It verifies mac1, decrypts the peer's static key and the timestamp, and
// stashes the handshake state for Response.
//
// It returns the peer's static public key — for the caller to match against its
// configured peers — and the initiation's TAI64N timestamp, which the caller
// must check is strictly newer than the last one seen from that peer to reject a
// replayed initiation (protocol paper §5.1). The preshared key is not used here,
// so it need not be known yet.
func (r *Responder) Consume(pkt []byte) (peerStatic [KeySize]byte, timestamp [wire.TimestampLen]byte, err error) {
	msg, err := wire.ParseHandshakeInitiation(pkt)
	if err != nil {
		return peerStatic, timestamp, err
	}

	// mac1 first: reject anything not aimed at our static key before doing any
	// Diffie-Hellman. mac2 is the caller's to check, with a CookieChecker, and
	// only under load: it depends on the source address and on whether the
	// server is busy, neither of which a Responder knows.
	over1, _, ok := wire.MACRegions(pkt)
	if !ok {
		return peerStatic, timestamp, wire.ErrMalformed
	}
	want := mac128(r.mac1Key[:], macOver(over1, r.typeInitiation))
	if want != msg.MAC1 {
		return peerStatic, timestamp, ErrMAC1
	}

	r.peerIndex = msg.Sender

	// initiator.chaining_key = HASH(CONSTRUCTION)
	r.ck = hashOf([]byte(construction))
	// initiator.hash = HASH(HASH(chaining_key || IDENTIFIER) || responder.static_public)
	ih := hashOf(r.ck[:], []byte(identifier))
	r.h = hashOf(ih[:], r.localStatic.PublicKey().Bytes())

	peerEph, err := ecdh.X25519().NewPublicKey(msg.Ephemeral[:])
	if err != nil {
		return peerStatic, timestamp, fmt.Errorf("noise: peer ephemeral: %w", err)
	}
	r.peerEph = peerEph

	// initiator.hash = HASH(initiator.hash || msg.unencrypted_ephemeral)
	r.h = hashOf(r.h[:], msg.Ephemeral[:])
	// chaining_key = KDF1(chaining_key, msg.unencrypted_ephemeral)
	r.ck = kdf1(&r.ck, msg.Ephemeral[:])

	// DH(responder.static_private, initiator.ephemeral_public) mirrors the
	// initiator's DH(ephemeral_private, responder.static_public).
	es, err := r.localStatic.ECDH(peerEph)
	if err != nil {
		return peerStatic, timestamp, fmt.Errorf("noise: ephemeral-static DH: %w", err)
	}
	ck, k := kdf2(&r.ck, es)
	r.ck = ck

	// msg.encrypted_static opens to the peer's static public key.
	aead, err := cryptoutil.NewChaCha20Poly1305(k[:])
	if err != nil {
		return peerStatic, timestamp, err
	}
	staticBytes, err := aead.Open(nil, zeroNonce[:], msg.Static[:], r.h[:])
	if err != nil {
		return peerStatic, timestamp, ErrDecrypt
	}
	ps, err := ecdh.X25519().NewPublicKey(staticBytes)
	if err != nil {
		return peerStatic, timestamp, fmt.Errorf("noise: peer static: %w", err)
	}
	r.peerStatic = ps
	// initiator.hash = HASH(initiator.hash || msg.encrypted_static)
	r.h = hashOf(r.h[:], msg.Static[:])

	// DH(responder.static_private, initiator.static_public).
	ss, err := r.localStatic.ECDH(ps)
	if err != nil {
		return peerStatic, timestamp, fmt.Errorf("noise: static-static DH: %w", err)
	}
	ck, k = kdf2(&r.ck, ss)
	r.ck = ck

	// msg.encrypted_timestamp opens to the TAI64N timestamp.
	aead, err = cryptoutil.NewChaCha20Poly1305(k[:])
	if err != nil {
		return peerStatic, timestamp, err
	}
	ts, err := aead.Open(nil, zeroNonce[:], msg.Timestamp[:], r.h[:])
	if err != nil {
		return peerStatic, timestamp, ErrDecrypt
	}
	// initiator.hash = HASH(initiator.hash || msg.encrypted_timestamp)
	r.h = hashOf(r.h[:], msg.Timestamp[:])

	copy(r.timestamp[:], ts)
	copy(peerStatic[:], r.peerStatic.Bytes())
	r.consumed = true
	return peerStatic, r.timestamp, nil
}

// Response builds message type 2 (protocol paper §5.4.3) and derives the
// transport keys. psk is the preshared key the caller selected for this peer
// (its zero value for a peer without one). It must be called once, after
// Consume.
//
// The returned message's mac1 is stamped for the peer's static key; mac2 is left
// zero. A non-zero one would need a cookie the *initiator* had sent us, which it
// does only when it is itself under load and refusing responses -- the case
// this responder does not handle; see the package README's caveats.
func (r *Responder) Response(psk [KeySize]byte) ([]byte, *Keypair, error) {
	if !r.consumed {
		return nil, nil, errors.New("noise: response before initiation was consumed")
	}

	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("noise: ephemeral key: %w", err)
	}
	localIdx, err := randomIndex()
	if err != nil {
		return nil, nil, err
	}

	msg := &wire.HandshakeResponse{Sender: localIdx, Receiver: r.peerIndex}
	// msg.unencrypted_ephemeral = DH_PUBKEY(responder.ephemeral_private)
	copy(msg.Ephemeral[:], eph.PublicKey().Bytes())
	// responder.hash = HASH(responder.hash || msg.unencrypted_ephemeral)
	r.h = hashOf(r.h[:], msg.Ephemeral[:])
	// chaining_key = KDF1(chaining_key, msg.unencrypted_ephemeral)
	r.ck = kdf1(&r.ck, msg.Ephemeral[:])

	// DH(responder.ephemeral_private, initiator.ephemeral_public)
	ee, err := eph.ECDH(r.peerEph)
	if err != nil {
		return nil, nil, fmt.Errorf("noise: ephemeral-ephemeral DH: %w", err)
	}
	r.ck = kdf1(&r.ck, ee)

	// DH(responder.ephemeral_private, initiator.static_public)
	se, err := eph.ECDH(r.peerStatic)
	if err != nil {
		return nil, nil, fmt.Errorf("noise: ephemeral-static DH: %w", err)
	}
	r.ck = kdf1(&r.ck, se)

	// chaining_key, tau, key = KDF3(chaining_key, preshared_key)
	ck, tau, k := kdf3(&r.ck, psk[:])
	r.ck = ck
	// responder.hash = HASH(responder.hash || tau)
	r.h = hashOf(r.h[:], tau[:])

	// msg.encrypted_nothing = AEAD(key, 0, "", responder.hash)
	aead, err := cryptoutil.NewChaCha20Poly1305(k[:])
	if err != nil {
		return nil, nil, err
	}
	empty := aead.Seal(nil, zeroNonce[:], nil, r.h[:])
	copy(msg.Empty[:], empty)
	// responder.hash = HASH(responder.hash || msg.encrypted_nothing)
	r.h = hashOf(r.h[:], msg.Empty[:])

	buf := make([]byte, wire.SizeHandshakeResponse)
	out, err := msg.Marshal(buf)
	if err != nil {
		return nil, nil, err
	}
	// mac1 authenticates the response to the peer's static key; mac2 stays zero.
	peerMAC1Key := hashOf([]byte(labelMAC1), r.peerStatic.Bytes())
	m1 := mac128(peerMAC1Key[:], macOver(out[:wire.SizeHandshakeResponse-2*wire.MACSize], r.typeResponse))
	copy(out[wire.SizeHandshakeResponse-2*wire.MACSize:], m1[:])

	// The responder's sending key is the initiator's receiving key, so the pair
	// is swapped relative to the initiator's.
	recv, send := kdf2(&r.ck, nil)
	return out, &Keypair{
		Send:   send,
		Recv:   recv,
		Local:  localIdx,
		Remote: r.peerIndex,
	}, nil
}
