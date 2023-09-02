package vmess

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"golang.org/x/crypto/chacha20poly1305"
)

func TestChaCHa20Poly1305(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	_, _ = rand.Read(key)
	aead, err := chacha20poly1305.New(key)
	assert.NoError(t, err)

	none := make([]byte, aead.NonceSize())
	_, _ = rand.Read(none)

	plaintext := []byte("hello world")

	cryptTxt := aead.Seal(nil, none, plaintext, nil)
	t.Log(hex.EncodeToString(cryptTxt))

	decryptTxt, err := aead.Open(nil, none, cryptTxt, nil)
	assert.NoError(t, err)
	t.Log(string(decryptTxt))
}
