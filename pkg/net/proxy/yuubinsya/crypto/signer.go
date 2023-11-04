package crypto

import (
	"crypto"
	"crypto/ed25519"
	"io"

	"golang.org/x/crypto/hkdf"
)

type Signer interface {
	Sign(rand io.Reader, digest []byte) (signature []byte, err error)
	SignatureSize() int
	Verify(message, sig []byte) bool
}

type Ed25519 struct {
	privatekey ed25519.PrivateKey
}

func NewEd25519(hash Hash, key []byte) Signer {
	r := hkdf.New(hash.New, key, make([]byte, hash.Size()), []byte("ed25519-signature"))
	seed := make([]byte, ed25519.SeedSize)
	_, _ = io.ReadFull(r, seed)

	return &Ed25519{ed25519.NewKeyFromSeed(seed)}
}

func (Ed25519) SignatureSize() int { return ed25519.SignatureSize }
func (e Ed25519) Verify(message, sig []byte) bool {
	return ed25519.Verify(e.privatekey.Public().(ed25519.PublicKey), message, sig)
}
func (e Ed25519) Sign(rand io.Reader, digest []byte) (signature []byte, err error) {
	return e.privatekey.Sign(rand, digest, crypto.Hash(0))
}
