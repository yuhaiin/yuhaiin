package aead

import (
	"crypto"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"hash"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

func Salt(password []byte) []byte {
	h := sha256.New()
	h.Write(password)
	h.Write([]byte("+s@1t"))
	return h.Sum(nil)
}

func newAead(aead Aead, password []byte) (cipher.AEAD, error) {
	var key []byte
	switch aead.KeySize() {
	case 32:
		// for backwards compatibility, here we just use sha256
		salted := append(password, []byte("yuubinsya-salt-")...)
		key32 := sha256.Sum256(salted)
		key = key32[:]
	default:
		prt, err := hkdf.Extract(sha256.New, key, nil)
		if err != nil {
			return nil, err
		}

		key, err = hkdf.Expand(sha256.New, prt, "yuubinsya-salt-", aead.KeySize())
		if err != nil {
			return nil, err
		}
	}

	return aead.New(key[:])
}

type Hash interface {
	New() hash.Hash
	Size() int
}

var Sha256 = sha256Hash{}

type sha256Hash struct{}

func (sha256Hash) New() hash.Hash { return sha256.New() }
func (sha256Hash) Size() int      { return sha256.Size }

type Signer interface {
	Sign(rand io.Reader, digest []byte) (signature []byte, err error)
	SignatureSize() int
	Verify(message, sig []byte) bool
}

type Aead interface {
	New([]byte) (cipher.AEAD, error)
	KeySize() int
	NonceSize() int
	Name() []byte
}

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

var Chacha20poly1305 = chacha20poly1305Aead{}

type chacha20poly1305Aead struct{}

func (chacha20poly1305Aead) New(key []byte) (cipher.AEAD, error) { return chacha20poly1305.New(key) }
func (chacha20poly1305Aead) KeySize() int                        { return chacha20poly1305.KeySize }
func (chacha20poly1305Aead) NonceSize() int                      { return chacha20poly1305.NonceSize }
func (chacha20poly1305Aead) Name() []byte                        { return []byte("chacha20poly1305-key") }

var XChacha20poly1305 = xchacha20poly1305Aead{}

type xchacha20poly1305Aead struct{}

func (xchacha20poly1305Aead) New(key []byte) (cipher.AEAD, error) { return chacha20poly1305.NewX(key) }
func (xchacha20poly1305Aead) KeySize() int                        { return chacha20poly1305.KeySize }
func (xchacha20poly1305Aead) NonceSize() int                      { return chacha20poly1305.NonceSizeX }
func (xchacha20poly1305Aead) Name() []byte                        { return []byte("xchacha20poly1305-key") }
