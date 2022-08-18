package httpserver

import (
	"bytes"
	"crypto/aes"
	"testing"

	"golang.org/x/crypto/chacha20"
)

func TestXxx(t *testing.T) {
	encChacha20, err := chacha20.NewUnauthenticatedCipher(
		bytes.Repeat([]byte{0x01}, chacha20.KeySize),
		bytes.Repeat([]byte{0x02}, chacha20.NonceSize),
	)
	if err != nil {
		t.Fatal(err)
	}

	plain := []byte{0x01, 0x02, 0x03}

	t.Log(plain)
	encChacha20.XORKeyStream(plain, plain)
	t.Log(plain)

	decChacha20, err := chacha20.NewUnauthenticatedCipher(
		bytes.Repeat([]byte{0x01}, chacha20.KeySize),
		bytes.Repeat([]byte{0x02}, chacha20.NonceSize),
	)
	if err != nil {
		t.Fatal(err)
	}
	decChacha20.XORKeyStream(plain, plain)
	t.Log(plain)
}

func TestAes(t *testing.T) {
	enc, err := aes.NewCipher(bytes.Repeat([]byte{0x01}, 32))
	if err != nil {
		t.Fatal(err)
	}

	plain := bytes.Repeat([]byte{0x01, 0x02, 0x03, 0x04}, aes.BlockSize/4)

	enc.Encrypt(plain, plain)
	t.Log(plain)

	enc.Decrypt(plain, plain)
	t.Log(plain)
}
