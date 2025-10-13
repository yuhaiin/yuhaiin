package aead

import (
	crand "crypto/rand"
	"io"
	"math/rand/v2"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestEncodePacket(t *testing.T) {
	password := make([]byte, rand.IntN(60000))
	_, _ = io.ReadFull(crand.Reader, password)
	auth, err := GetAuth(password)
	assert.NoError(t, err)

	data := make([]byte, rand.IntN(60000))
	_, _ = io.ReadFull(crand.Reader, data)

	buf := make([]byte, auth.NonceSize()+auth.Overhead()+len(data))
	encode := encodePacket(buf, data, auth)

	decoded, err := decodePacket(encode, auth)
	assert.NoError(t, err)
	assert.MustEqual(t, data, decoded)
}
