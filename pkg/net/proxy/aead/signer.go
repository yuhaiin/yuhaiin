package aead

import (
	"crypto"
	"crypto/ed25519"
	"crypto/hkdf"
	"io"
)

type Ed25519 struct {
	privatekey ed25519.PrivateKey
}

func NewEd25519(hash Hash, key []byte) Signer {
	prt, _ := hkdf.Extract(hash.New, key, make([]byte, hash.Size()))
	seed, _ := hkdf.Expand(hash.New, prt, "ed25519-signature", ed25519.SeedSize)
	return &Ed25519{ed25519.NewKeyFromSeed(seed)}
}

func (Ed25519) SignatureSize() int { return ed25519.SignatureSize }
func (e Ed25519) Verify(message, sig []byte) bool {
	return ed25519.Verify(e.privatekey.Public().(ed25519.PublicKey), message, sig)
}
func (e Ed25519) Sign(rand io.Reader, digest []byte) (signature []byte, err error) {
	return e.privatekey.Sign(rand, digest, crypto.Hash(0))
}
