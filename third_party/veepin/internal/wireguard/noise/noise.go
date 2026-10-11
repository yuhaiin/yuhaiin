// Package noise implements WireGuard's Noise_IKpsk2 handshake as the initiator.
//
// The handshake is a fixed sequence of DH operations, KDF steps and AEAD calls
// with no negotiation — WireGuard has no cipher suites — so the code below reads
// as a transcription of the protocol paper §5.4.2/§5.4.3 rather than as a state
// machine with choices. Each step's comment names the paper's line it implements,
// because the only way to be sure this is right is to check it against the paper
// line by line.
//
// The responder's mirror image is responder.go, and the cookie exchange both
// sides of it need under load is cookie.go.
package noise

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/xen0bit/veepin/internal/cryptoutil"
	"github.com/xen0bit/veepin/internal/wireguard/wire"
)

// Protocol constants (protocol paper §5.4). LABEL_COOKIE is in cookie.go.
const (
	construction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	identifier   = "WireGuard v1 zx2c4 Jason@zx2c4.com"
	labelMAC1    = "mac1----"
)

// KeySize is the length of a Curve25519 key and of every symmetric key here.
const KeySize = wire.KeySize

var (
	// ErrDecrypt reports a handshake message that failed authentication: a wrong
	// peer key, a wrong preshared key, or tampering. They are deliberately
	// indistinguishable.
	ErrDecrypt = errors.New("noise: handshake decryption failed")
	// ErrWrongReceiver reports a response addressed to a different session.
	//
	// There is no mac1 error here: an initiator only ever computes mac1, since
	// verifying one is the responder's job.
	ErrWrongReceiver = errors.New("noise: response for an unknown session")
)

// zeroNonce is the all-zero ChaCha20-Poly1305 nonce. Every handshake AEAD uses
// it: each call has a freshly derived key, so the nonce never repeats under one
// key. Transport packets are the opposite — one key, a counter nonce.
var zeroNonce [12]byte

// Keypair is the transport keying material a completed handshake yields.
type Keypair struct {
	// Send encrypts our outbound transport packets; Recv opens the peer's.
	Send [KeySize]byte
	Recv [KeySize]byte
	// Local is the index we told the peer to address us by; Remote is the index
	// the peer told us to address it by.
	Local  uint32
	Remote uint32
}

// Initiator drives one handshake attempt. It is single-use: a failed or expired
// handshake means a fresh Initiator, which is also what keeps the ephemeral key
// from being reused.
type Initiator struct {
	localStatic  *ecdh.PrivateKey
	remoteStatic *ecdh.PublicKey
	presharedKey [KeySize]byte

	// mac1Key is HASH(LABEL_MAC1 || responder.static_public), precomputed since
	// every initiation to this peer uses it; cookieKey is the same over
	// LABEL_COOKIE, which a cookie reply is encrypted under.
	mac1Key   key
	cookieKey key
	// cookie, when non-zero, is the responder's token mac2 is computed with
	// (SetCookie).
	cookie Cookie

	ephemeral *ecdh.PrivateKey
	localIdx  uint32
	ck        key // chaining key
	h         key // handshake hash

	// lastMAC1 is the mac1 we sent, which a cookie reply is authenticated
	// against (protocol paper §5.4.7).
	lastMAC1 [wire.MACSize]byte
	sent     bool

	// typeInitiation is Config.TypeInitiation: the word mac1 is computed over.
	typeInitiation uint32
}

// Config is one peer's identity material.
type Config struct {
	// LocalStatic is our private key.
	LocalStatic [KeySize]byte
	// RemoteStatic is the peer's public key.
	RemoteStatic [KeySize]byte
	// PresharedKey is the optional symmetric key mixed into the handshake. The
	// zero value means "no PSK", which the protocol handles by mixing zeros —
	// there is no separate code path.
	PresharedKey [KeySize]byte

	// TypeInitiation / TypeResponse are AmneziaWG's H1 and H2: the 4-octet
	// message-type words that replace the stock constants 1 and 2 on the wire.
	// Zero means stock.
	//
	// They live here, rather than only in the obfuscation layer, because mac1 is
	// computed over the message *including* its type word. Substituting the type
	// after the MAC is stamped invalidates it — which is invisible between two
	// veepin endpoints, since both would compute over the stock value and agree,
	// and is rejected immediately by amneziawg-go ("invalid mac1"). Only the MAC
	// computation uses these; parsing stays on the stock constants throughout.
	TypeInitiation uint32
	TypeResponse   uint32
}

// macOver returns the byte range mac1 authenticates, with the message-type word
// replaced by typeWord when that is non-zero. It copies only when a substitution
// is needed, so the stock path allocates nothing extra.
func macOver(over []byte, typeWord uint32) []byte {
	if typeWord == 0 || len(over) < 4 {
		return over
	}
	patched := make([]byte, len(over))
	copy(patched, over)
	binary.LittleEndian.PutUint32(patched[0:4], typeWord)
	return patched
}

// NewInitiator prepares a handshake to the configured peer.
func NewInitiator(cfg Config) (*Initiator, error) {
	priv, err := ecdh.X25519().NewPrivateKey(cfg.LocalStatic[:])
	if err != nil {
		return nil, fmt.Errorf("noise: local static key: %w", err)
	}
	pub, err := ecdh.X25519().NewPublicKey(cfg.RemoteStatic[:])
	if err != nil {
		return nil, fmt.Errorf("noise: remote static key: %w", err)
	}
	i := &Initiator{
		localStatic:    priv,
		remoteStatic:   pub,
		presharedKey:   cfg.PresharedKey,
		mac1Key:        hashOf([]byte(labelMAC1), cfg.RemoteStatic[:]),
		cookieKey:      hashOf([]byte(labelCookie), cfg.RemoteStatic[:]),
		typeInitiation: cfg.TypeInitiation,
	}
	return i, nil
}

// LocalIndex is the sender index this handshake claimed, which the peer will put
// in its response's receiver field and in every transport packet it sends us.
func (i *Initiator) LocalIndex() uint32 { return i.localIdx }

// Initiation builds message type 1 and returns it marshalled, ready to send.
//
// The steps below are the paper's §5.4.2 in order; the comments quote its
// pseudocode so the two can be diffed by eye.
func (i *Initiator) Initiation() ([]byte, error) {
	if i.sent {
		return nil, errors.New("noise: initiation already sent")
	}

	// initiator.chaining_key = HASH(CONSTRUCTION)
	i.ck = hashOf([]byte(construction))
	// initiator.hash = HASH(HASH(initiator.chaining_key || IDENTIFIER) || responder.static_public)
	ih := hashOf(i.ck[:], []byte(identifier))
	i.h = hashOf(ih[:], i.remoteStatic.Bytes())

	// initiator.ephemeral_private = DH_GENERATE()
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("noise: ephemeral key: %w", err)
	}
	i.ephemeral = eph

	idx, err := randomIndex()
	if err != nil {
		return nil, err
	}
	i.localIdx = idx

	msg := &wire.HandshakeInitiation{Sender: i.localIdx}
	// msg.unencrypted_ephemeral = DH_PUBKEY(initiator.ephemeral_private)
	copy(msg.Ephemeral[:], eph.PublicKey().Bytes())
	// initiator.hash = HASH(initiator.hash || msg.unencrypted_ephemeral)
	i.h = hashOf(i.h[:], msg.Ephemeral[:])
	// temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
	// initiator.chaining_key = HMAC(temp, 0x1)
	i.ck = kdf1(&i.ck, msg.Ephemeral[:])

	// temp = HMAC(initiator.chaining_key, DH(initiator.ephemeral_private, responder.static_public))
	// initiator.chaining_key = HMAC(temp, 0x1)
	// key = HMAC(temp, initiator.chaining_key || 0x2)
	es, err := eph.ECDH(i.remoteStatic)
	if err != nil {
		return nil, fmt.Errorf("noise: ephemeral-static DH: %w", err)
	}
	ck, k := kdf2(&i.ck, es)
	i.ck = ck

	// msg.encrypted_static = AEAD(key, 0, initiator.static_public, initiator.hash)
	aead, err := cryptoutil.NewChaCha20Poly1305(k[:])
	if err != nil {
		return nil, err
	}
	static := aead.Seal(nil, zeroNonce[:], i.localStatic.PublicKey().Bytes(), i.h[:])
	copy(msg.Static[:], static)
	// initiator.hash = HASH(initiator.hash || msg.encrypted_static)
	i.h = hashOf(i.h[:], msg.Static[:])

	// temp = HMAC(initiator.chaining_key, DH(initiator.static_private, responder.static_public))
	// initiator.chaining_key = HMAC(temp, 0x1)
	// key = HMAC(temp, initiator.chaining_key || 0x2)
	ss, err := i.localStatic.ECDH(i.remoteStatic)
	if err != nil {
		return nil, fmt.Errorf("noise: static-static DH: %w", err)
	}
	ck, k = kdf2(&i.ck, ss)
	i.ck = ck

	// msg.encrypted_timestamp = AEAD(key, 0, TAI64N(), initiator.hash)
	aead, err = cryptoutil.NewChaCha20Poly1305(k[:])
	if err != nil {
		return nil, err
	}
	ts := wire.Timestamp(time.Now())
	stamp := aead.Seal(nil, zeroNonce[:], ts[:], i.h[:])
	copy(msg.Timestamp[:], stamp)
	// initiator.hash = HASH(initiator.hash || msg.encrypted_timestamp)
	i.h = hashOf(i.h[:], msg.Timestamp[:])

	buf := make([]byte, wire.SizeHandshakeInitiation)
	out, err := msg.Marshal(buf)
	if err != nil {
		return nil, err
	}
	// The MACs authenticate the marshalled bytes, so they are stamped in place
	// rather than computed into the struct.
	if err := i.addMACs(out); err != nil {
		return nil, err
	}
	i.sent = true
	return out, nil
}

// addMACs computes mac1 and mac2 over the marshalled message.
//
//	msg.mac1 = MAC(HASH(LABEL_MAC1 || responder.static_public), msg[0:offsetof(msg.mac1)])
//	msg.mac2 = MAC(last_received_cookie, msg[0:offsetof(msg.mac2)])  // or zeros
//
// mac2 is zero unless the caller set a cookie, which it has only if the
// responder sent a cookie reply -- which it does only under load. The caller
// decides whether a cookie it holds is still fresh (CookieRefreshTime).
func (i *Initiator) addMACs(msg []byte) error {
	over1, over2, ok := wire.MACRegions(msg)
	if !ok {
		return errors.New("noise: message has no MAC regions")
	}
	m1 := mac128(i.mac1Key[:], macOver(over1, i.typeInitiation))
	copy(msg[len(over1):len(over1)+wire.MACSize], m1[:])
	i.lastMAC1 = m1
	// over2 now includes the mac1 just written, as the paper's offsetof says.
	mac2 := msg[len(over2) : len(over2)+wire.MACSize]
	if i.cookie == (Cookie{}) {
		clear(mac2)
		return nil
	}
	m2 := mac128(i.cookie[:], macOver(over2, i.typeInitiation))
	copy(mac2, m2[:])
	return nil
}

// Consume processes the peer's message type 2 and derives the transport keys.
//
// The steps are the paper's §5.4.3, from the initiator's side: where the paper
// says responder.ephemeral_private, we have only its public half, so each DH is
// computed with our own private key against it.
func (i *Initiator) Consume(pkt []byte) (*Keypair, error) {
	if !i.sent {
		return nil, errors.New("noise: response before initiation")
	}
	msg, err := wire.ParseHandshakeResponse(pkt)
	if err != nil {
		return nil, err
	}
	if msg.Receiver != i.localIdx {
		return nil, ErrWrongReceiver
	}

	peerEph, err := ecdh.X25519().NewPublicKey(msg.Ephemeral[:])
	if err != nil {
		return nil, fmt.Errorf("noise: peer ephemeral: %w", err)
	}

	// responder.hash = HASH(responder.hash || msg.unencrypted_ephemeral)
	h := hashOf(i.h[:], msg.Ephemeral[:])
	// temp = HMAC(responder.chaining_key, msg.unencrypted_ephemeral)
	// responder.chaining_key = HMAC(temp, 0x1)
	ck := kdf1(&i.ck, msg.Ephemeral[:])

	// temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.ephemeral_public))
	// responder.chaining_key = HMAC(temp, 0x1)
	ee, err := i.ephemeral.ECDH(peerEph)
	if err != nil {
		return nil, fmt.Errorf("noise: ephemeral-ephemeral DH: %w", err)
	}
	ck = kdf1(&ck, ee)

	// temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.static_public))
	// responder.chaining_key = HMAC(temp, 0x1)
	se, err := i.localStatic.ECDH(peerEph)
	if err != nil {
		return nil, fmt.Errorf("noise: static-ephemeral DH: %w", err)
	}
	ck = kdf1(&ck, se)

	// temp = HMAC(responder.chaining_key, preshared_key)
	// responder.chaining_key = HMAC(temp, 0x1)
	// temp2 = HMAC(temp, responder.chaining_key || 0x2)
	// key = HMAC(temp, temp2 || 0x3)
	ck2, tau, k := kdf3(&ck, i.presharedKey[:])
	ck = ck2
	// responder.hash = HASH(responder.hash || temp2)
	h = hashOf(h[:], tau[:])

	// msg.encrypted_nothing = AEAD(key, 0, "", responder.hash)
	aead, err := cryptoutil.NewChaCha20Poly1305(k[:])
	if err != nil {
		return nil, err
	}
	if _, err := aead.Open(nil, zeroNonce[:], msg.Empty[:], h[:]); err != nil {
		// A wrong peer key, a wrong PSK and a forged packet all land here, and
		// must stay indistinguishable.
		return nil, ErrDecrypt
	}
	// responder.hash = HASH(responder.hash || msg.encrypted_nothing)
	h = hashOf(h[:], msg.Empty[:])

	i.ck, i.h = ck, h

	// temp1 = HMAC(initiator.chaining_key, "")
	// temp2 = HMAC(temp1, 0x1)
	// temp3 = HMAC(temp1, temp2 || 0x2)
	// initiator.sending_key = temp2; initiator.receiving_key = temp3
	send, recv := kdf2(&i.ck, nil)
	return &Keypair{
		Send:   send,
		Recv:   recv,
		Local:  i.localIdx,
		Remote: msg.Sender,
	}, nil
}

// randomIndex picks a session index. It is a random 32-bit value rather than a
// counter so that indices carry no information about how many sessions we have
// had.
func randomIndex() (uint32, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("noise: session index: %w", err)
	}
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24, nil
}

// PublicKey returns the public half of a Curve25519 private key, for config
// validation and for logging which identity we present.
func PublicKey(private [KeySize]byte) ([KeySize]byte, error) {
	var out [KeySize]byte
	priv, err := ecdh.X25519().NewPrivateKey(private[:])
	if err != nil {
		return out, fmt.Errorf("noise: private key: %w", err)
	}
	copy(out[:], priv.PublicKey().Bytes())
	return out, nil
}
