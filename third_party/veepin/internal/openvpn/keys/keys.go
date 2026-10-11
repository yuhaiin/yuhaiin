// Package keys implements OpenVPN's "key method 2" key exchange and the key
// derivation that turns it into data-channel keys.
//
// After the TLS handshake, each side sends a key_source over the control channel
// — the client a 48-byte pre-master plus two 32-byte randoms, the server just
// the two randoms. Both sides then run OpenVPN's key derivation, which is two
// passes of the TLS 1.0 PRF (MD5 and SHA1 P_hash XORed together, RFC 2246 §5):
// the pre-master and the random1 pair yield a master secret, and the master with
// the random2 pair and both session IDs yields a 256-byte key block. The block
// is sliced into two directions' cipher and HMAC material; for AES-256-GCM the
// cipher slot gives the 32-byte key and the HMAC slot the 8-byte implicit IV.
//
// The wire layouts and PRF construction are from OpenVPN's ssl.c
// (key_method_2_write/read, generate_key_expansion, openvpn_PRF). Multi-byte
// lengths are big-endian.
package keys

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
)

const (
	preMasterLen = 48
	randomLen    = 32
	keyMethod2   = 2
	keyBlockLen  = 256 // two directions of (64-byte cipher slot + 64-byte HMAC slot)
	cipherSlot   = 64
	hmacSlot     = 64

	// GCMKeyLen and ImplicitIVLen are the AES-256-GCM data-key sizes taken from
	// each direction's slots: the full cipher key, and the nonce tail that
	// prefixes the packet ID to form the 12-byte GCM nonce.
	GCMKeyLen     = 32
	ImplicitIVLen = 8

	masterSecretLabel = "OpenVPN master secret"
	keyExpansionLabel = "OpenVPN key expansion"
)

var (
	// ErrShortMessage reports a key-method-2 message too short to parse.
	ErrShortMessage = errors.New("keys: key method 2 message truncated")
	// ErrBadKeyMethod reports a message whose key-method byte is not 2.
	ErrBadKeyMethod = errors.New("keys: unsupported key method")
)

// KeySource is one peer's random key material. The client fills all three
// fields; a server message carries only the two randoms.
type KeySource struct {
	PreMaster [preMasterLen]byte
	Random1   [randomLen]byte
	Random2   [randomLen]byte
}

// NewClientKeySource generates a client's random key material.
func NewClientKeySource() (*KeySource, error) {
	ks := &KeySource{}
	for _, b := range [][]byte{ks.PreMaster[:], ks.Random1[:], ks.Random2[:]} {
		if _, err := rand.Read(b); err != nil {
			return nil, fmt.Errorf("keys: random: %w", err)
		}
	}
	return ks, nil
}

// SessionID is a control-channel session identifier, mixed into key expansion.
type SessionID [8]byte

// DataKeys is the derived AES-256-GCM material for both directions. Encrypt* is
// what this side seals outbound packets with; Decrypt* opens the peer's.
type DataKeys struct {
	EncryptKey [GCMKeyLen]byte
	EncryptIV  [ImplicitIVLen]byte
	DecryptKey [GCMKeyLen]byte
	DecryptIV  [ImplicitIVLen]byte
}

// CBCKeys is the derived AES-256-CBC material for both directions: a 32-byte
// AES key and the full 64-byte HMAC slot per direction (the CBC data channel
// uses the digest-sized prefix of the HMAC slot as its authentication key).
type CBCKeys struct {
	EncryptKey  [GCMKeyLen]byte
	EncryptHMAC [hmacSlot]byte
	DecryptKey  [GCMKeyLen]byte
	DecryptHMAC [hmacSlot]byte
}

// KeySource2 pairs the client's and server's key material for derivation.
type KeySource2 struct {
	Client KeySource
	Server KeySource
}

// deriveSlots runs OpenVPN's two-stage PRF and returns this side's send and
// receive key slots (each a 64-byte cipher slot and 64-byte HMAC slot). isServer
// selects the direction: the client seals with the first slot and opens with the
// second, and the server the reverse, so the two ends' keys line up.
func (ks *KeySource2) deriveSlots(clientSID, serverSID SessionID, isServer bool) (sendCipher, sendHMAC, recvCipher, recvHMAC []byte) {
	master := prf(ks.Client.PreMaster[:], concat(masterSecretLabel, ks.Client.Random1[:], ks.Server.Random1[:]), preMasterLen)
	seed := concat(keyExpansionLabel, ks.Client.Random2[:], ks.Server.Random2[:], clientSID[:], serverSID[:])
	block := prf(master, seed, keyBlockLen)

	// keys[0] = block[0:128] (cipher[0:64] || hmac[64:128]); keys[1] the next 128.
	slot0Cipher := block[0:cipherSlot]
	slot0HMAC := block[cipherSlot : cipherSlot+hmacSlot]
	slot1Cipher := block[128 : 128+cipherSlot]
	slot1HMAC := block[128+cipherSlot : keyBlockLen]

	sendCipher, sendHMAC = slot0Cipher, slot0HMAC
	recvCipher, recvHMAC = slot1Cipher, slot1HMAC
	if isServer {
		sendCipher, sendHMAC = slot1Cipher, slot1HMAC
		recvCipher, recvHMAC = slot0Cipher, slot0HMAC
	}
	return sendCipher, sendHMAC, recvCipher, recvHMAC
}

// Derive runs OpenVPN's key derivation and slices out the AES-256-GCM data keys:
// each direction's 32-byte cipher key and the 8-byte implicit IV that prefixes
// the packet ID to form the GCM nonce.
func (ks *KeySource2) Derive(clientSID, serverSID SessionID, isServer bool) DataKeys {
	sendCipher, sendHMAC, recvCipher, recvHMAC := ks.deriveSlots(clientSID, serverSID, isServer)
	var dk DataKeys
	copy(dk.EncryptKey[:], sendCipher[:GCMKeyLen])
	copy(dk.EncryptIV[:], sendHMAC[:ImplicitIVLen])
	copy(dk.DecryptKey[:], recvCipher[:GCMKeyLen])
	copy(dk.DecryptIV[:], recvHMAC[:ImplicitIVLen])
	return dk
}

// DeriveCBC runs the same key derivation and slices out the AES-256-CBC data
// keys: each direction's 32-byte cipher key and full HMAC slot (the CBC cipher
// uses the digest-sized prefix as its HMAC key).
func (ks *KeySource2) DeriveCBC(clientSID, serverSID SessionID, isServer bool) CBCKeys {
	sendCipher, sendHMAC, recvCipher, recvHMAC := ks.deriveSlots(clientSID, serverSID, isServer)
	var ck CBCKeys
	copy(ck.EncryptKey[:], sendCipher[:GCMKeyLen])
	copy(ck.EncryptHMAC[:], sendHMAC)
	copy(ck.DecryptKey[:], recvCipher[:GCMKeyLen])
	copy(ck.DecryptHMAC[:], recvHMAC)
	return ck
}

// concat builds a PRF seed: the label (no null terminator) followed by the
// remaining byte slices in order.
func concat(label string, parts ...[]byte) []byte {
	n := len(label)
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	out = append(out, label...)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// prf is the TLS 1.0 PRF: the secret is split in half, P_MD5 keyed on the first
// half and P_SHA1 on the second are each run over the seed, and the two streams
// are XORed. For an odd-length secret the halves overlap by one byte.
func prf(secret, seed []byte, n int) []byte {
	half := (len(secret) + 1) / 2
	s1 := secret[:half]
	s2 := secret[len(secret)-half:]
	out := pHash(md5.New, s1, seed, n)
	sha := pHash(sha1.New, s2, seed, n)
	for i := range out {
		out[i] ^= sha[i]
	}
	return out
}

// pHash is TLS's P_hash(secret, seed) = HMAC(secret, A(1)||seed) ||
// HMAC(secret, A(2)||seed) || … where A(0)=seed and A(i)=HMAC(secret, A(i-1)),
// truncated to n octets.
func pHash(h func() hash.Hash, secret, seed []byte, n int) []byte {
	mac := hmac.New(h, secret)
	out := make([]byte, 0, n)
	a := seed
	for len(out) < n {
		mac.Reset()
		mac.Write(a)
		a = mac.Sum(nil)

		mac.Reset()
		mac.Write(a)
		mac.Write(seed)
		out = mac.Sum(out)
	}
	return out[:n]
}

// MarshalClient encodes a client key-method-2 message: the leading zero word,
// the method byte, the full key source, the OCC options string, the username and
// password (empty strings are valid), and the peer-info block advertising this
// client's capabilities.
func (ks *KeySource) MarshalClient(options, username, password, peerInfo string) []byte {
	var b []byte
	b = append(b, 0, 0, 0, 0) // leading uint32(0)
	b = append(b, keyMethod2)
	b = append(b, ks.PreMaster[:]...)
	b = append(b, ks.Random1[:]...)
	b = append(b, ks.Random2[:]...)
	b = appendString(b, options)
	b = appendString(b, username)
	b = appendString(b, password)
	// peer_info is length-prefixed but, unlike the strings above, not
	// null-terminated (OpenVPN reads exactly the prefixed length).
	b = appendUint16(b, len(peerInfo))
	b = append(b, peerInfo...)
	return b
}

// ParseServer decodes a server key-method-2 message: the leading zero word, the
// method byte, the server's two randoms, and the options string. Trailing
// fields (auth, peer-info) are ignored.
func ParseServer(b []byte) (*KeySource, string, error) {
	// 4 (zero) + 1 (method) + 2*randomLen + 2 (options length) minimum.
	if len(b) < 5+2*randomLen+2 {
		return nil, "", ErrShortMessage
	}
	if b[4] != keyMethod2 {
		return nil, "", ErrBadKeyMethod
	}
	off := 5
	ks := &KeySource{}
	off += copy(ks.Random1[:], b[off:off+randomLen])
	off += copy(ks.Random2[:], b[off:off+randomLen])
	options, _, err := readString(b, off)
	if err != nil {
		return nil, "", err
	}
	return ks, options, nil
}

// appendString appends an OpenVPN write_string field: a uint16 length that
// includes the trailing null, then the bytes and the null.
func appendString(b []byte, s string) []byte {
	b = appendUint16(b, len(s)+1)
	b = append(b, s...)
	return append(b, 0)
}

func appendUint16(b []byte, n int) []byte {
	return binary.BigEndian.AppendUint16(b, uint16(n))
}

// readString reads a write_string field at off, returning the string without its
// trailing null and the offset past it.
func readString(b []byte, off int) (string, int, error) {
	if off+2 > len(b) {
		return "", 0, ErrShortMessage
	}
	n := int(binary.BigEndian.Uint16(b[off:]))
	off += 2
	if n == 0 || off+n > len(b) {
		return "", 0, ErrShortMessage
	}
	// n includes the trailing null.
	s := string(b[off : off+n-1])
	return s, off + n, nil
}
