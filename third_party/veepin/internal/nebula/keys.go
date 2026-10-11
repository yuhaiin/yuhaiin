package nebula

// Private key files.
//
// nebula-cert writes keys as PEM with its own banners, holding the raw key
// bytes rather than PKCS#8. A host needs two kinds: the X25519 key its
// certificate is bound to, used for Noise key agreement, and — only on a CA —
// the Ed25519 key that signs certificates.
//
// Encrypted (Argon2-wrapped) private keys are not supported. veepin has no
// passphrase prompt in its connect path, so a key it cannot read unattended
// would only fail later and less clearly.

import (
	"crypto/ed25519"
	"encoding/pem"
	"fmt"
)

const (
	x25519PrivateKeyBanner  = "NEBULA X25519 PRIVATE KEY"
	ed25519PrivateKeyBanner = "NEBULA ED25519 PRIVATE KEY"
)

// X25519KeySize is the length of a raw X25519 private key.
const X25519KeySize = 32

// UnmarshalX25519PrivateKeyPEM reads the host key a certificate is bound to.
func UnmarshalX25519PrivateKeyPEM(b []byte) ([]byte, error) {
	raw, err := decodeKeyPEM(b, x25519PrivateKeyBanner)
	if err != nil {
		return nil, err
	}
	if len(raw) != X25519KeySize {
		return nil, fmt.Errorf("nebula: X25519 private key is %d bytes, want %d", len(raw), X25519KeySize)
	}
	return raw, nil
}

// UnmarshalEd25519PrivateKeyPEM reads a CA signing key.
func UnmarshalEd25519PrivateKeyPEM(b []byte) (ed25519.PrivateKey, error) {
	raw, err := decodeKeyPEM(b, ed25519PrivateKeyBanner)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("nebula: Ed25519 private key is %d bytes, want %d", len(raw), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(raw), nil
}

func decodeKeyPEM(b []byte, banner string) ([]byte, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("nebula: no PEM block found in key file")
	}
	if block.Type != banner {
		return nil, fmt.Errorf("nebula: key file holds %q, want %q", block.Type, banner)
	}
	return block.Bytes, nil
}
