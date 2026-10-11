package cryptoutil

import (
	"crypto/cipher"
	"hash"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
)

// This file is why the module has a dependency at all.
//
// WireGuard fixes its crypto: ChaCha20-Poly1305 and BLAKE2s, with no
// negotiation. Neither is in the standard library, so unlike IKEv2 — which
// negotiates algorithms and happens to negotiate ones crypto/aes and
// crypto/sha256 cover — WireGuard cannot be built on stdlib alone.
//
// golang.org/x/crypto is the Go team's own module and carries the AVX2/NEON
// assembly for ChaCha20-Poly1305. Hand-rolling these was the alternative; it
// would have been several times slower on the data path and a far larger
// security surface than the bundled MD4 in internal/ikev2/eap, which is a legacy
// hash used in one corner rather than the AEAD protecting every packet.
//
// These primitives are protocol-agnostic and named for what they are, like the
// rest of this package. IKEv2 can reach ChaCha20-Poly1305 through
// internal/ikev2/transform whenever its transform ID is wired up.

// ChaCha20Poly1305KeySize is the key length in octets for both the AEAD
// constructors below.
const ChaCha20Poly1305KeySize = chacha20poly1305.KeySize

// NewChaCha20Poly1305 returns the AEAD (RFC 8439) keyed by a 32-octet key, with
// a 12-octet nonce. This is WireGuard's transport and handshake cipher.
func NewChaCha20Poly1305(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.New(key)
}

// NewXChaCha20Poly1305 returns the extended-nonce variant (24-octet nonce),
// keyed by a 32-octet key. WireGuard uses it for cookie replies, where the nonce
// is random rather than a counter and so needs the larger space.
func NewXChaCha20Poly1305(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.NewX(key)
}

// BLAKE2sSize is the BLAKE2s-256 digest length in octets.
const BLAKE2sSize = blake2s.Size

// BLAKE2s128Size is the BLAKE2s-128 digest length in octets.
const BLAKE2s128Size = 16

// NewBLAKE2s returns an unkeyed BLAKE2s-256 hash (RFC 7693).
func NewBLAKE2s() hash.Hash {
	// A nil key selects the unkeyed mode; the size is valid, so the error is
	// unreachable and would signal a misuse of this package rather than input.
	h, err := blake2s.New256(nil)
	if err != nil {
		panic("cryptoutil: BLAKE2s-256 unkeyed: " + err.Error())
	}
	return h
}

// NewBLAKE2s256MAC returns a keyed BLAKE2s-256 hash — BLAKE2's native MAC mode,
// which needs no HMAC construction around it. The key must be at most 32 octets.
func NewBLAKE2s256MAC(key []byte) (hash.Hash, error) {
	return blake2s.New256(key)
}

// NewBLAKE2s128MAC returns a keyed BLAKE2s-128 hash. This is the 128-bit digest
// WireGuard calls MAC(): mac1, mac2 and the cookie are all this width, not the
// 256-bit one.
func NewBLAKE2s128MAC(key []byte) (hash.Hash, error) {
	return blake2s.New128(key)
}
