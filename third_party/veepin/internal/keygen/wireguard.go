package keygen

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// WireGuardKeypair generates a Curve25519 keypair and returns both halves
// base64-encoded, matching WireGuard's key format.
func WireGuardKeypair() (privB64, pubB64 string, err error) {
	var priv, pub [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return "", "", fmt.Errorf("keygen: wireguard: %w", err)
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	curve25519.ScalarBaseMult(&pub, &priv)

	return base64.StdEncoding.EncodeToString(priv[:]),
		base64.StdEncoding.EncodeToString(pub[:]), nil
}

// WireGuardPublicKey derives the public half of a WireGuard private key. The
// management plane uses it to recover a listener's server public key when the
// operator supplied their own private key and no generated public-key was ever
// stored: the client config needs the server's public half, and deriving beats
// asking the operator to remember it.
func WireGuardPublicKey(privB64 string) (string, error) {
	priv, err := base64.StdEncoding.DecodeString(privB64)
	if err != nil {
		return "", fmt.Errorf("keygen: wireguard private key not base64: %w", err)
	}
	if len(priv) != 32 {
		return "", fmt.Errorf("keygen: wireguard private key is %d bytes, want 32", len(priv))
	}
	var privArr, pubArr [32]byte
	copy(privArr[:], priv)
	curve25519.ScalarBaseMult(&pubArr, &privArr)
	return base64.StdEncoding.EncodeToString(pubArr[:]), nil
}

// genWireGuardKeypair returns the keypair as an option map for the keygen
// dispatcher. The public half is what the operator distributes to clients; an
// earlier version computed and discarded it, which made the panel's "generate"
// one-sided: the server key was created but no one could learn its public half.
func genWireGuardKeypair() (map[string]string, error) {
	priv, pub, err := WireGuardKeypair()
	if err != nil {
		return nil, err
	}
	return map[string]string{
		"private-key": priv,
		"public-key":  pub,
	}, nil
}
