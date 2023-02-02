package yuubinsya

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"golang.org/x/crypto/chacha20poly1305"
)

func TestXxx(t *testing.T) {
	c1, err := ecdh.P384().GenerateKey(rand.Reader)
	assert.NoError(t, err)
	c2, err := ecdh.P384().GenerateKey(rand.Reader)
	assert.NoError(t, err)

	p1 := c1.PublicKey().Bytes()
	p2 := c2.PublicKey().Bytes()

	pp1, err := ecdh.P384().NewPublicKey(p2)
	assert.NoError(t, err)
	pp2, err := ecdh.P384().NewPublicKey(p1)
	assert.NoError(t, err)

	cc1, err := c1.ECDH(pp1)
	assert.NoError(t, err)
	cc2, err := c2.ECDH(pp2)
	assert.NoError(t, err)

	t.Log(p1, p2, len(p1), len(p2))
	t.Log(cc1, cc2)

	z := make([]byte, 32)
	epk := ed25519.NewKeyFromSeed(z)
	signature, err := epk.Sign(rand.Reader, cc1, crypto.Hash(0))
	assert.NoError(t, err)

	t.Log(signature, len(signature))
}

func TestXx2x(t *testing.T) {
	a, err := chacha20poly1305.New(make([]byte, chacha20poly1305.KeySize))
	assert.NoError(t, err)

	nouce := make([]byte, chacha20poly1305.NonceSize)
	dst := make([]byte, 1024)
	ret := a.Seal(dst[:0], nouce, []byte{1, 2}, nil)

	t.Log(dst, ret)

}
