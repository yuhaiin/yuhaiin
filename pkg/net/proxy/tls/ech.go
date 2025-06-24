package tls

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"errors"

	"golang.org/x/crypto/cryptobyte"
)

//copy from https://github.com/c2FmZQ/ech/blob/main/config.go

var ErrDecodeError = errors.New("decode error")

// ECHConfig is a serialized Encrypted Client Hello (ECH) ECHConfig.
type ECHConfig []byte

type Key = tls.EncryptedClientHelloKey

// Config returns a serialized Encrypted Client Hello (ECH) Config List.
func ECHConfigList(configs []ECHConfig) ([]byte, error) {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16LengthPrefixed(func(c *cryptobyte.Builder) {
		for _, cfg := range configs {
			c.AddBytes(cfg)
		}
	})
	return b.Bytes()
}

// ParseECHConfigList parses a serialized Encrypted Client Hello (ECH) Config List.
func ParseECHConfigList(configList []byte) ([]ECHConfigSpec, error) {
	s := cryptobyte.String(configList)
	var ss cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&ss) {
		return nil, ErrDecodeError
	}
	var list []ECHConfigSpec
	for !ss.Empty() {
		spec, err := parseECHConfig(&ss)
		if err != nil {
			return nil, err
		}
		list = append(list, spec)
	}
	return list, nil
}

// NewECHConfig generates an Encrypted Client Hello (ECH) Config and a private key.
// It currently supports:
//   - DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305.
//   - DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM.
//   - DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM.
func NewECHConfig(id uint8, publicName []byte) (*ecdh.PrivateKey, ECHConfig, error) {
	if l := len(publicName); l == 0 || l > 255 {
		return nil, nil, errors.New("invalid public name length")
	}
	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	c := ECHConfigSpec{
		Version:   0xfe0d,
		ID:        id,
		KEM:       0x0020, // DHKEM(X25519, HKDF-SHA256)
		PublicKey: privKey.PublicKey().Bytes(),
		CipherSuites: []CipherSuite{
			{
				KDF:  0x0001, // HKDF-SHA256
				AEAD: 0x0003, // ChaCha20Poly1305
			},
			{
				KDF:  0x0001, // HKDF-SHA256
				AEAD: 0x0002, // AES-256-GCM
			},
			{
				KDF:  0x0001, // HKDF-SHA256
				AEAD: 0x0001, // AES-128-GCM
			},
		},
		MaximumNameLength: uint8(min(len(publicName)+16, 255)),
		PublicName:        publicName,
	}
	conf, err := c.Bytes()
	if err != nil {
		return nil, nil, err
	}
	return privKey, conf, nil
}

// Spec returns the structured version of cfg.
func (cfg ECHConfig) Spec() (ECHConfigSpec, error) {
	return parseECHConfig((*cryptobyte.String)(&cfg))
}

func parseECHConfig(s *cryptobyte.String) (ECHConfigSpec, error) {
	var out ECHConfigSpec
	if !s.ReadUint16(&out.Version) {
		return out, ErrDecodeError
	}
	if out.Version != 0xfe0d {
		return out, ErrDecodeError
	}
	var ss cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&ss) {
		return out, ErrDecodeError
	}
	if !ss.ReadUint8(&out.ID) {
		return out, ErrDecodeError
	}
	if !ss.ReadUint16(&out.KEM) {
		return out, ErrDecodeError
	}
	if !ss.ReadUint16LengthPrefixed((*cryptobyte.String)(&out.PublicKey)) {
		return out, ErrDecodeError
	}
	var cs cryptobyte.String
	if !ss.ReadUint16LengthPrefixed(&cs) {
		return out, ErrDecodeError
	}
	for !cs.Empty() {
		var suite CipherSuite
		if !cs.ReadUint16(&suite.KDF) {
			return out, ErrDecodeError
		}
		if !cs.ReadUint16(&suite.AEAD) {
			return out, ErrDecodeError
		}
		out.CipherSuites = append(out.CipherSuites, suite)
	}
	if !ss.ReadUint8(&out.MaximumNameLength) {
		return out, ErrDecodeError
	}
	if !ss.ReadUint8LengthPrefixed((*cryptobyte.String)(&out.PublicName)) {
		return out, ErrDecodeError
	}
	return out, nil
}

// ECHConfigSpec represents an Encrypted Client Hello (ECH) Config. It is specified
// in Section 4 of https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni/
type ECHConfigSpec struct {
	PublicKey         []byte
	CipherSuites      []CipherSuite
	PublicName        []byte
	Version           uint16
	KEM               uint16
	ID                uint8
	MaximumNameLength uint8
}

type CipherSuite struct {
	KDF  uint16
	AEAD uint16
}

// Bytes returns the serialized version of the Encrypted Client Hello (ECH)
// Config.
func (c ECHConfigSpec) Bytes() (ECHConfig, error) {
	if l := len(c.PublicName); l == 0 || l > 255 {
		return nil, errors.New("invalid public name length")
	}
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(c.Version)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(c.ID)
		b.AddUint16(c.KEM)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(c.PublicKey)
		})
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, cs := range c.CipherSuites {
				b.AddUint16(cs.KDF)
				b.AddUint16(cs.AEAD)
			}
		})
		b.AddUint8(uint8(min(len(c.PublicName)+16, 255)))
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(c.PublicName)
		})
		b.AddUint16(0) // extensions
	})
	conf, err := b.Bytes()
	if err != nil {
		return nil, err
	}
	return conf, nil
}
