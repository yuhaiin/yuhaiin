package aead

import (
	"crypto/cipher"
	"crypto/sha256"
	"hash"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

type auth struct {
	cipher.AEAD
}

func (a *auth) Key() []byte {
	return nil
}

func (a *auth) KeySize() int {
	return 0
}

func GetAuth(password []byte) (*auth, error) {
	salted := append(password, []byte("yuubinsya-salt-")...)
	key := sha256.Sum256(salted)

	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	return &auth{
		AEAD: aead,
	}, nil
}

type Hash interface {
	New() hash.Hash
	Size() int
}

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
