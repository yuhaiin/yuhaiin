package keygen

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"path/filepath"
)

// genEd25519 generates an Ed25519 keypair and writes it to <dir>/ed25519_key
// in PKCS#8 PEM format. It is usable as an SSH host key (OpenSSH 6.5+ reads
// this format directly) and as a Nebula key. The result is keyed by optKey so
// it works for both "host-key" (ssh) and "key" (nebula).
func genEd25519(dir, optKey string) (map[string]string, error) {
	if err := ensureDir(dir); err != nil {
		return nil, err
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("keygen: ed25519: %w", err)
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("keygen: pkcs8 wrapping: %w", err)
	}
	// Through writePEM rather than its own OpenFile: that one re-chmods an
	// existing file, which is what stops a regeneration over key material an
	// older version left world-readable from keeping that mode.
	path := filepath.Join(dir, "ed25519_key")
	if err := writePEM(path, "PRIVATE KEY", pkcs8); err != nil {
		return nil, err
	}

	return map[string]string{optKey: path}, nil
}
