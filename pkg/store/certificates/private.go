package certificates

import (
	"bytes"
	"errors"
)

// Secret prevents accidental JSON serialization and common formatted logging.
// Bytes is an explicit private-material access; no management read API exposes it.
type Secret struct{ value []byte }

func NewSecret(value []byte) Secret           { return Secret{bytes.Clone(value)} }
func (s Secret) Bytes() []byte                { return bytes.Clone(s.value) }
func (s Secret) Empty() bool                  { return len(s.value) == 0 }
func (s Secret) String() string               { return "[redacted]" }
func (s Secret) GoString() string             { return "[redacted]" }
func (s Secret) MarshalJSON() ([]byte, error) { return []byte("null"), nil }
func (s *Secret) UnmarshalJSON([]byte) error {
	return errors.New("private material requires an explicit write-only input")
}

type Material struct {
	CertificatePEM []byte
	PrivateKey     Secret
}
