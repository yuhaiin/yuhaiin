// Package transform maps IKEv2 IANA transform IDs onto concrete cryptographic
// primitives.
//
// It is the seam between the wire protocol and the algorithm implementations:
// internal/payload owns the transform-ID registry, internal/cryptoutil owns the
// primitives and knows nothing about IKEv2, and this package is the only place
// that translates between them. Keeping the lookup here is what lets cryptoutil
// stay reusable by other VPN protocols, whose registries number the same
// algorithms differently.
//
// Adding an algorithm means adding a case here plus a constructor in cryptoutil.
package transform

import (
	"crypto/ecdh"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"github.com/xen0bit/veepin/internal/cryptoutil"
	"github.com/xen0bit/veepin/internal/ikev2/payload"
)

// Cipher returns the SK (handshake) cipher for an ENCR transform ID and key
// length in bits; 0 bits selects the algorithm's default.
func Cipher(encrID uint16, keyBits int) (cryptoutil.SKCipher, error) {
	switch encrID {
	case payload.ENCR_AES_GCM_16:
		return cryptoutil.NewAESGCMSKCipher(keyBits)
	case payload.ENCR_CHACHA20_P:
		return cryptoutil.NewChaCha20Poly1305SKCipher()
	case payload.ENCR_AES_CBC:
		return cryptoutil.NewAESCBCSKCipher(keyBits)
	default:
		return nil, fmt.Errorf("transform: unsupported ENCR %d", encrID)
	}
}

// ESPCrypter returns a prepared data-path crypter for an ESP transform. encKey
// carries the 4-octet GCM salt for AEAD suites; integID/integKey are used only
// by non-AEAD (CBC) suites.
func ESPCrypter(encrID uint16, keyBits int, encKey []byte, integID uint16, integKey []byte) (cryptoutil.ESPCrypter, error) {
	switch encrID {
	case payload.ENCR_AES_GCM_16:
		return cryptoutil.NewAESGCMESPCrypter(keyBits, encKey)
	case payload.ENCR_CHACHA20_P:
		return cryptoutil.NewChaCha20Poly1305ESPCrypter(encKey)
	case payload.ENCR_AES_CBC:
		integ, err := Integrity(integID)
		if err != nil {
			return nil, err
		}
		return cryptoutil.NewAESCBCESPCrypter(keyBits, encKey, integ, integKey)
	default:
		return nil, fmt.Errorf("transform: unsupported ESP ENCR %d", encrID)
	}
}

// PRF returns the pseudorandom function for a PRF transform ID.
func PRF(id uint16) (*cryptoutil.PRF, error) {
	var h func() hash.Hash
	switch id {
	case payload.PRF_HMAC_SHA1:
		h = sha1.New
	case payload.PRF_HMAC_SHA2_256:
		h = sha256.New
	case payload.PRF_HMAC_SHA2_384:
		h = sha512.New384
	case payload.PRF_HMAC_SHA2_512:
		h = sha512.New
	default:
		return nil, fmt.Errorf("transform: unsupported PRF %d", id)
	}
	return cryptoutil.NewHMACPRF(h), nil
}

// Integrity returns the integrity transform for an AUTH transform ID. The key
// length is the hash output size and the ICV is truncated per RFC 4868.
func Integrity(id uint16) (*cryptoutil.Integrity, error) {
	switch id {
	case payload.AUTH_HMAC_SHA1_96:
		return cryptoutil.NewHMACIntegrity(sha1.New, 20, 12), nil
	case payload.AUTH_HMAC_SHA2_256_128:
		return cryptoutil.NewHMACIntegrity(sha256.New, 32, 16), nil
	case payload.AUTH_HMAC_SHA2_384_192:
		return cryptoutil.NewHMACIntegrity(sha512.New384, 48, 24), nil
	case payload.AUTH_HMAC_SHA2_512_256:
		return cryptoutil.NewHMACIntegrity(sha512.New, 64, 32), nil
	default:
		return nil, fmt.Errorf("transform: unsupported integrity %d", id)
	}
}

// DH returns the Diffie-Hellman group for a DH transform ID. The NIST curves
// transmit bare X||Y on the wire (RFC 5903), so their point prefix is stripped;
// Curve25519 has no such prefix.
func DH(id uint16) (cryptoutil.DHGroup, error) {
	switch id {
	case payload.DH_CURVE25519:
		return cryptoutil.NewECDH(ecdh.X25519(), false), nil
	case payload.DH_ECP_256:
		return cryptoutil.NewECDH(ecdh.P256(), true), nil
	case payload.DH_ECP_384:
		return cryptoutil.NewECDH(ecdh.P384(), true), nil
	case payload.DH_ECP_521:
		return cryptoutil.NewECDH(ecdh.P521(), true), nil
	case payload.DH_MODP_2048:
		return cryptoutil.NewMODP2048(), nil
	default:
		return nil, fmt.Errorf("transform: unsupported DH group %d", id)
	}
}
