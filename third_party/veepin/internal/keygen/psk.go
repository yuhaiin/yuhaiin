package keygen

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// genPSK returns 32 random bytes hex-encoded as an inline pre-shared key,
// keyed by optKey so it works regardless of whether the protocol calls it
// "psk" (ikev2, l2tp) or "group-psk" (cisco).
func genPSK(optKey string) (map[string]string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("keygen: psk: %w", err)
	}
	return map[string]string{optKey: hex.EncodeToString(raw)}, nil
}
