package crypto

import (
	"crypto/cipher"
	"crypto/sha256"

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
