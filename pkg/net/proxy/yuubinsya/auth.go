package yuubinsya

import "crypto/cipher"

type Auth interface {
	cipher.AEAD
	KeySize() int
	Key() []byte
}

type plainAuth struct {
	password    []byte
	passwordLen int
}

func NewPlainAuth(password []byte) Auth {
	return &plainAuth{
		password:    password,
		passwordLen: len(password),
	}
}

func (a *plainAuth) KeySize() int {
	return a.passwordLen
}

func (a *plainAuth) Key() []byte {
	return a.password
}

func (a *plainAuth) Seal(dst, nonce, plaintext, additionalData []byte) []byte { return nil }
func (a *plainAuth) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	return nil, nil
}

func (a *plainAuth) NonceSize() int { return 0 }

func (a *plainAuth) Overhead() int { return 0 }
