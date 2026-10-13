package reality

import (
	"crypto/mldsa"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestHexDecode(t *testing.T) {
	private, public, err := GenerateKey()
	assert.NoError(t, err)

	fmt.Printf("Private key: %v\nPublic key: %v\n", private, public)

	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	assert.NoError(t, err)
	fmt.Printf("Seed: %v\nVerify: %v\n",
		base64.RawURLEncoding.EncodeToString(key.Bytes()),
		base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()))
}

func TestParseMLDSA65PrivateKey(t *testing.T) {
	var seed [mldsa.PrivateKeySize]byte
	for i := range seed {
		seed[i] = byte(i + 1)
	}

	key, err := parseMLDSA65PrivateKey(base64.RawURLEncoding.EncodeToString(seed[:]))
	if err != nil {
		t.Fatal(err)
	}
	if key == nil {
		t.Fatal("expected ML-DSA-65 private key")
	}

	message := []byte("REALITY ML-DSA-65 signature")
	signature, err := key.SignDeterministic(message, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := mldsa.Verify(key.PublicKey(), message, signature, nil); err != nil {
		t.Fatalf("verify ML-DSA-65 signature: %v", err)
	}
	if err := mldsa.Verify(key.PublicKey(), []byte("tampered"), signature, nil); err == nil {
		t.Fatal("ML-DSA-65 verification accepted a tampered message")
	}
}

func TestParseMLDSA65PrivateKeyOptional(t *testing.T) {
	key, err := parseMLDSA65PrivateKey("")
	if err != nil || key != nil {
		t.Fatalf("empty seed should disable ML-DSA-65: key=%v, err=%v", key, err)
	}
}

func TestParseMLDSA65PrivateKeyInvalid(t *testing.T) {
	for _, tc := range []struct {
		name string
		seed string
	}{
		{name: "invalid base64", seed: "!"},
		{name: "short seed", seed: base64.RawURLEncoding.EncodeToString(make([]byte, mldsa.PrivateKeySize-1))},
		{name: "long seed", seed: base64.RawURLEncoding.EncodeToString(make([]byte, mldsa.PrivateKeySize+1))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if key, err := parseMLDSA65PrivateKey(tc.seed); err == nil || key != nil {
				t.Fatalf("expected invalid seed error: key=%v, err=%v", key, err)
			}
		})
	}
}
