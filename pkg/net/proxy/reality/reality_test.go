package reality

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"golang.org/x/crypto/curve25519"
)

func TestHexDecode(t *testing.T) {

	var input_base64 string

	var err error
	var privateKey []byte
	var publicKey []byte
	if len(input_base64) > 0 {
		privateKey, err = base64.RawURLEncoding.DecodeString(input_base64)
		if err != nil {
			assert.NoError(t, err)
		}
		if len(privateKey) != curve25519.ScalarSize {
			assert.NoError(t, errors.New("Invalid length of private key."))
		}
	}

	if privateKey == nil {
		privateKey = make([]byte, curve25519.ScalarSize)
		if _, err = rand.Read(privateKey); err != nil {
			assert.NoError(t, err)
		}
	}

	// Modify random bytes using algorithm described at:
	// https://cr.yp.to/ecdh.html.
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	if publicKey, err = curve25519.X25519(privateKey, curve25519.Basepoint); err != nil {
		assert.NoError(t, err)
	}

	fmt.Printf("Private key: %v\nPublic key: %v",
		base64.RawURLEncoding.EncodeToString(privateKey),
		base64.RawURLEncoding.EncodeToString(publicKey))

	t.Log(hex.DecodeString(""))
}
