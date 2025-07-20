package reality

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func TestHexDecode(t *testing.T) {
	private, public, err := GenerateKey()
	assert.NoError(t, err)

	fmt.Printf("Private key: %v\nPublic key: %v\n", private, public)

	var seed [32]byte
	_, _ = rand.Read(seed[:])
	pub, _ := mldsa65.NewKeyFromSeed(&seed)
	fmt.Printf("Seed: %v\nVerify: %v\n",
		base64.RawURLEncoding.EncodeToString(seed[:]),
		base64.RawURLEncoding.EncodeToString(pub.Bytes()))
}
