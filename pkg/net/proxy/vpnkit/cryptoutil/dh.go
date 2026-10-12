// Package cryptoutil implements the cryptographic primitives a VPN transport
// needs: Diffie-Hellman groups, keyed PRFs and prf+ expansion, integrity
// transforms, and the handshake (SKCipher) and data-path (ESPCrypter) ciphers.
//
// It is deliberately protocol-agnostic: nothing here knows about IKEv2 or its
// IANA transform-ID registry. Mapping a negotiated transform ID onto one of
// these primitives is the job of a protocol package (for IKEv2, that is
// internal/ikev2/transform), which keeps this layer reusable by any protocol.
package cryptoutil

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"math/big"
)

// DHGroup abstracts a Diffie-Hellman group: generate an ephemeral key, expose
// the public value in wire form, and compute a shared secret.
type DHGroup interface {
	// Generate returns the public key bytes (wire form) for a fresh private key.
	Generate() (pub []byte, err error)
	// ComputeSecret takes the peer public key bytes and returns the shared secret.
	ComputeSecret(peerPub []byte) ([]byte, error)
}

// NewECDH returns an ECDH group over curve. When stripPointPrefix is set, the
// uncompressed-point marker (0x04) that crypto/ecdh puts in front of an X||Y
// public value is removed on the wire and re-added on parse: the NIST curves
// transmit bare X||Y (RFC 5903), whereas X25519 has no such prefix.
func NewECDH(curve ecdh.Curve, stripPointPrefix bool) DHGroup {
	return &ecdhGroup{curve: curve, stripPointPrefix: stripPointPrefix}
}

// NewMODP2048 returns the 2048-bit MODP group (RFC 3526).
func NewMODP2048() DHGroup {
	return &modpGroup{prime: modp2048Prime, g: big.NewInt(2), size: 256}
}

// --- ECDH-based groups (X25519 and the NIST curves) ---

type ecdhGroup struct {
	curve            ecdh.Curve
	stripPointPrefix bool
	priv             *ecdh.PrivateKey
}

func (g *ecdhGroup) Generate() ([]byte, error) {
	priv, err := g.curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	g.priv = priv
	pub := priv.PublicKey().Bytes()
	if g.stripPointPrefix && len(pub) > 0 && pub[0] == 0x04 {
		pub = pub[1:]
	}
	return pub, nil
}

func (g *ecdhGroup) ComputeSecret(peerPub []byte) ([]byte, error) {
	if g.priv == nil {
		return nil, fmt.Errorf("cryptoutil: DH private key not generated")
	}
	wire := peerPub
	if g.stripPointPrefix {
		// Re-add the uncompressed-point prefix crypto/ecdh expects.
		wire = append([]byte{0x04}, peerPub...)
	}
	pub, err := g.curve.NewPublicKey(wire)
	if err != nil {
		return nil, fmt.Errorf("cryptoutil: invalid peer public key: %w", err)
	}
	return g.priv.ECDH(pub)
}

// --- MODP group (classic finite-field DH, RFC 3526) ---

type modpGroup struct {
	id    uint16
	prime *big.Int
	g     *big.Int
	size  int // shared-secret byte length (prime size)
	priv  *big.Int
}

func (m *modpGroup) ID() uint16 { return m.id }

func (m *modpGroup) Generate() ([]byte, error) {
	// Private exponent: a random value in [2, prime-2]. 320 bits of entropy is
	// comfortably above the security level of MODP-2048.
	priv, err := rand.Int(rand.Reader, new(big.Int).Sub(m.prime, big.NewInt(2)))
	if err != nil {
		return nil, err
	}
	priv.Add(priv, big.NewInt(2))
	m.priv = priv
	pub := new(big.Int).Exp(m.g, priv, m.prime)
	return leftPad(pub.Bytes(), m.size), nil
}

func (m *modpGroup) ComputeSecret(peerPub []byte) ([]byte, error) {
	if m.priv == nil {
		return nil, fmt.Errorf("cryptoutil: DH private key not generated")
	}
	peer := new(big.Int).SetBytes(peerPub)
	// Reject degenerate public values (1, p-1, >=p) that force a weak secret.
	if peer.Cmp(big.NewInt(1)) <= 0 || peer.Cmp(new(big.Int).Sub(m.prime, big.NewInt(1))) >= 0 {
		return nil, fmt.Errorf("cryptoutil: invalid MODP peer public value")
	}
	secret := new(big.Int).Exp(peer, m.priv, m.prime)
	return leftPad(secret.Bytes(), m.size), nil
}

func leftPad(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}
