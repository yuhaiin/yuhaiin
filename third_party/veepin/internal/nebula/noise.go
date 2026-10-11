package nebula

// The Noise handshake.
//
// Nebula keys its tunnels with the Noise Protocol Framework's IX pattern:
//
//	-> e, s
//	<- e, ee, se, s, es
//
// Two messages, one round trip, and both sides authenticated by the end of it.
// The "I" means the initiator sends its static key in the clear in the first
// message, which is what lets a responder look up the peer's certificate before
// it has done any asymmetric work. That costs initiator identity hiding, which
// nebula does not need — a mesh member's public key is not a secret.
//
// A note on the name, because it is a trap. Nebula's message subtype constant
// is HandshakeIXPSK0 and its handshake config sets PresharedKey and
// PresharedKeyPlacement, which reads like Noise_IXpsk0. It is not. The library
// only activates the PSK machinery when `len(psk) > 0 || placement >= 2`, and
// nebula passes an empty key at placement 0, so no PSK token is mixed in and
// the protocol name carries no psk0 modifier. The wire protocol is plain
// Noise_IX. This matters concretely: the protocol name seeds the handshake
// hash, so building this against the psk0 name would fail every handshake with
// nothing in the error to say why.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/xen0bit/veepin/internal/cryptoutil"
)

// Noise protocol names. These are hashed to seed the handshake state, so they
// are part of the wire format and must match the peer exactly.
const (
	noiseProtocolAESGCM     = "Noise_IX_25519_AESGCM_SHA256"
	noiseProtocolChaChaPoly = "Noise_IX_25519_ChaChaPoly_SHA256"
)

const (
	// keySize is the size of an X25519 key and of a Noise symmetric key.
	keySize = 32
	// tagSize is the AEAD authentication tag length.
	tagSize = 16
	// nonceLen is the 96-bit AEAD nonce both ciphers use.
	nonceLen = 12
)

var errHandshake = errors.New("nebula: noise handshake failed")

// noiseCipher selects the AEAD. Nebula defaults to AES-GCM and switches to
// ChaCha20-Poly1305 when configured, so both are implemented.
type noiseCipher uint8

const (
	cipherAESGCM noiseCipher = iota
	cipherChaChaPoly
)

func (c noiseCipher) protocolName() string {
	if c == cipherChaChaPoly {
		return noiseProtocolChaChaPoly
	}
	return noiseProtocolAESGCM
}

// aead builds the AEAD for a Noise symmetric key.
func (c noiseCipher) aead(key []byte) (cipher.AEAD, error) {
	if c == cipherChaChaPoly {
		return cryptoutil.NewChaCha20Poly1305(key)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// putNonce renders a Noise counter into dst (which must be nonceLen bytes). Both
// ciphers use a 96-bit nonce of four zero bytes followed by the counter, but
// AES-GCM writes it big-endian and ChaCha20-Poly1305 little-endian.
//
// It writes into a caller-supplied buffer rather than returning one so the data
// path can keep the nonce in memory it has already allocated: a fresh []byte
// returned here would escape to the heap through the cipher.AEAD interface, one
// allocation on every packet.
func (c noiseCipher) putNonce(dst []byte, n uint64) {
	dst[0], dst[1], dst[2], dst[3] = 0, 0, 0, 0
	if c == cipherChaChaPoly {
		binary.LittleEndian.PutUint64(dst[4:], n)
	} else {
		binary.BigEndian.PutUint64(dst[4:], n)
	}
}

// nonce renders a Noise counter into a fresh slice. Used only on the handshake
// path, where the extra allocation is negligible; the data path uses putNonce.
func (c noiseCipher) nonce(n uint64) []byte {
	nb := make([]byte, nonceLen)
	c.putNonce(nb, n)
	return nb
}

// hkdf2 is the Noise HKDF, returning the two outputs the pattern needs.
func hkdf2(ck []byte, ikm []byte) (o1, o2 [keySize]byte) {
	mac := hmac.New(sha256.New, ck)
	mac.Write(ikm)
	temp := mac.Sum(nil)

	mac = hmac.New(sha256.New, temp)
	mac.Write([]byte{0x01})
	copy(o1[:], mac.Sum(nil))

	mac = hmac.New(sha256.New, temp)
	mac.Write(o1[:])
	mac.Write([]byte{0x02})
	copy(o2[:], mac.Sum(nil))
	return o1, o2
}

// symmetricState is Noise's SymmetricState: the chaining key, the running
// transcript hash, and the current cipher key.
type symmetricState struct {
	cipher noiseCipher
	ck     [keySize]byte
	h      [keySize]byte
	k      [keySize]byte
	n      uint64
	hasKey bool
}

func newSymmetricState(c noiseCipher) *symmetricState {
	s := &symmetricState{cipher: c}
	name := []byte(c.protocolName())
	// Noise: a protocol name of 32 bytes or fewer is zero-padded rather than
	// hashed. Both of these names are shorter, but the branch keeps the rule
	// visible rather than implied.
	if len(name) <= keySize {
		copy(s.h[:], name)
	} else {
		s.h = sha256.Sum256(name)
	}
	s.ck = s.h
	return s
}

func (s *symmetricState) mixHash(data []byte) {
	sum := sha256.New()
	sum.Write(s.h[:])
	sum.Write(data)
	copy(s.h[:], sum.Sum(nil))
}

func (s *symmetricState) mixKey(ikm []byte) {
	s.ck, s.k = hkdf2(s.ck[:], ikm)
	s.n = 0
	s.hasKey = true
}

// encryptAndHash encrypts under the current key and folds the result into the
// transcript. Before the first DH there is no key, and Noise defines the
// operation as a plain MixHash — which is how the initiator's static key
// travels in the clear in an IX first message.
func (s *symmetricState) encryptAndHash(plaintext []byte) ([]byte, error) {
	if !s.hasKey {
		s.mixHash(plaintext)
		return plaintext, nil
	}
	aead, err := s.cipher.aead(s.k[:])
	if err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, s.cipher.nonce(s.n), plaintext, s.h[:])
	s.n++
	s.mixHash(ct)
	return ct, nil
}

func (s *symmetricState) decryptAndHash(ciphertext []byte) ([]byte, error) {
	if !s.hasKey {
		s.mixHash(ciphertext)
		return ciphertext, nil
	}
	aead, err := s.cipher.aead(s.k[:])
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, s.cipher.nonce(s.n), ciphertext, s.h[:])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errHandshake, err)
	}
	s.n++
	s.mixHash(ciphertext)
	return pt, nil
}

// split derives the two transport keys. The first is the initiator's sending
// key and the second the responder's.
func (s *symmetricState) split() (k1, k2 [keySize]byte) {
	return hkdf2(s.ck[:], nil)
}

// noiseHandshake runs one side of the IX exchange.
type noiseHandshake struct {
	ss        *symmetricState
	initiator bool

	s  *ecdh.PrivateKey // static
	e  *ecdh.PrivateKey // ephemeral
	rs []byte           // peer static
	re []byte           // peer ephemeral
}

// newNoiseHandshake starts an exchange using the host's static key.
func newNoiseHandshake(c noiseCipher, initiator bool, static *ecdh.PrivateKey) *noiseHandshake {
	hs := &noiseHandshake{
		ss:        newSymmetricState(c),
		initiator: initiator,
		s:         static,
	}
	// The library always mixes the prologue, and an empty prologue still
	// advances the hash, so this is not an optimisation that can be skipped.
	hs.ss.mixHash(nil)
	return hs
}

// PeerStatic returns the peer's static public key once it has been received.
func (hs *noiseHandshake) PeerStatic() []byte { return hs.rs }

// generateEphemeral installs the ephemeral keypair: the caller's, or a fresh one
// from crypto/rand when it passes nil.
//
// The seam is the *key* rather than the entropy behind it, deliberately, and the
// distinction stopped being cosmetic in Go 1.26. That release added the
// `cryptocustomrand` GODEBUG, which defaults to 0 for a go.mod at 1.26 or later
// and makes crypto/... APIs ignore the io.Reader they are handed. This function
// used to take one; at the 1.27 floor it would have been silently ignored and
// the known-answer vectors below would have been tested against fresh entropy.
// A parameter the runtime discards is worse than no parameter, so it is gone.
func (hs *noiseHandshake) generateEphemeral(eph *ecdh.PrivateKey) error {
	if eph != nil {
		hs.e = eph
		return nil
	}
	e, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	hs.e = e
	return nil
}

func dh(priv *ecdh.PrivateKey, pub []byte) ([]byte, error) {
	p, err := ecdh.X25519().NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("%w: bad peer key: %w", errHandshake, err)
	}
	return priv.ECDH(p)
}

// WriteMessage1 produces the initiator's message: -> e, s
//
// eph is nil everywhere except in tests, which supply a fixed ephemeral key to
// reproduce the vectors in noise_test.go. See generateEphemeral.
func (hs *noiseHandshake) WriteMessage1(payload []byte, eph *ecdh.PrivateKey) ([]byte, error) {
	if !hs.initiator {
		return nil, errors.New("nebula: responder cannot send the first handshake message")
	}
	if err := hs.generateEphemeral(eph); err != nil {
		return nil, err
	}

	out := append([]byte(nil), hs.e.PublicKey().Bytes()...)
	hs.ss.mixHash(hs.e.PublicKey().Bytes())

	// No key is established yet, so this is the static key in the clear.
	st, err := hs.ss.encryptAndHash(hs.s.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	out = append(out, st...)

	pl, err := hs.ss.encryptAndHash(payload)
	if err != nil {
		return nil, err
	}
	return append(out, pl...), nil
}

// ReadMessage1 consumes the initiator's message on the responder.
func (hs *noiseHandshake) ReadMessage1(msg []byte) ([]byte, error) {
	if hs.initiator {
		return nil, errors.New("nebula: initiator cannot read the first handshake message")
	}
	if len(msg) < 2*keySize {
		return nil, fmt.Errorf("%w: first message is %d bytes, want at least %d",
			errHandshake, len(msg), 2*keySize)
	}

	hs.re = append([]byte(nil), msg[:keySize]...)
	hs.ss.mixHash(hs.re)

	rs, err := hs.ss.decryptAndHash(msg[keySize : 2*keySize])
	if err != nil {
		return nil, err
	}
	hs.rs = append([]byte(nil), rs...)

	return hs.ss.decryptAndHash(msg[2*keySize:])
}

// WriteMessage2 produces the responder's message: <- e, ee, se, s, es
//
// eph is nil everywhere except in tests. See generateEphemeral.
func (hs *noiseHandshake) WriteMessage2(payload []byte, eph *ecdh.PrivateKey) ([]byte, error) {
	if hs.initiator {
		return nil, errors.New("nebula: initiator cannot send the second handshake message")
	}
	if err := hs.generateEphemeral(eph); err != nil {
		return nil, err
	}

	out := append([]byte(nil), hs.e.PublicKey().Bytes()...)
	hs.ss.mixHash(hs.e.PublicKey().Bytes())

	if err := hs.mixDH(hs.e, hs.re); err != nil { // ee
		return nil, err
	}
	if err := hs.mixDH(hs.e, hs.rs); err != nil { // se, from the responder's side
		return nil, err
	}

	// The static key is encrypted this time: ee and se have established a key.
	st, err := hs.ss.encryptAndHash(hs.s.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	out = append(out, st...)

	if err := hs.mixDH(hs.s, hs.re); err != nil { // es, from the responder's side
		return nil, err
	}

	pl, err := hs.ss.encryptAndHash(payload)
	if err != nil {
		return nil, err
	}
	return append(out, pl...), nil
}

// ReadMessage2 consumes the responder's message on the initiator.
func (hs *noiseHandshake) ReadMessage2(msg []byte) ([]byte, error) {
	if !hs.initiator {
		return nil, errors.New("nebula: responder cannot read the second handshake message")
	}
	// The peer's static key arrives encrypted here, so the message carries an
	// extra AEAD tag compared with the first.
	if len(msg) < 2*keySize+tagSize {
		return nil, fmt.Errorf("%w: second message is %d bytes, want at least %d",
			errHandshake, len(msg), 2*keySize+tagSize)
	}

	hs.re = append([]byte(nil), msg[:keySize]...)
	hs.ss.mixHash(hs.re)

	if err := hs.mixDH(hs.e, hs.re); err != nil { // ee
		return nil, err
	}
	if err := hs.mixDH(hs.s, hs.re); err != nil { // se, from the initiator's side
		return nil, err
	}

	rs, err := hs.ss.decryptAndHash(msg[keySize : 2*keySize+tagSize])
	if err != nil {
		return nil, err
	}
	hs.rs = append([]byte(nil), rs...)

	if err := hs.mixDH(hs.e, hs.rs); err != nil { // es, from the initiator's side
		return nil, err
	}

	return hs.ss.decryptAndHash(msg[2*keySize+tagSize:])
}

func (hs *noiseHandshake) mixDH(priv *ecdh.PrivateKey, pub []byte) error {
	secret, err := dh(priv, pub)
	if err != nil {
		return err
	}
	hs.ss.mixKey(secret)
	return nil
}

// Split returns the transport keys as (send, receive) for this side.
func (hs *noiseHandshake) Split() (send, recv [keySize]byte) {
	k1, k2 := hs.ss.split()
	if hs.initiator {
		return k1, k2
	}
	return k2, k1
}
