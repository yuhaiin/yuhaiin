// Package tlswrap implements OpenVPN's static-key control-channel protection:
// --tls-auth (an HMAC over every control packet) and --tls-crypt (authenticated
// encryption of every control packet). Both draw their keys from the same
// 2048-bit static key file and wrap the reliable control messages the control
// package produces, before they reach the socket.
//
// A Wrapper sits between the marshalled control packet and the wire: Wrap adds
// the protection on the way out, Unwrap checks and removes it on the way in. A
// nil Wrapper (or Mode none) is the plain profile, unchanged.
//
// The wire layouts are from OpenVPN's ssl_pkt.c (tls-auth, write_control_auth)
// and tls_crypt.c (tls-crypt). Every multi-byte field is big-endian.
package tlswrap

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// StaticKeyLen is the size of an OpenVPN static key: a struct key2 of two
// 128-byte keys, each a 64-byte cipher key followed by a 64-byte HMAC key.
const StaticKeyLen = 256

const (
	keyLen    = 128 // one struct key: cipher[64] || hmac[64]
	cipherOff = 0
	hmacOff   = 64
)

var (
	// ErrBadKey reports a static key file that is not a well-formed OpenVPN
	// static key (wrong header, wrong length, or non-hex body).
	ErrBadKey = errors.New("tlswrap: malformed static key")
)

// Direction is the --key-direction of a static key: it selects which of the two
// keys in the file a side uses to send and which to receive, so the two ends
// line up. tls-crypt is always Inverse on the client; tls-auth is configurable.
type Direction int

const (
	// Bidirectional uses key slot 0 for both directions (the default when
	// --tls-auth is given no direction argument).
	Bidirectional Direction = iota
	// Normal sends with slot 0 and receives with slot 1 (--key-direction 0,
	// the server's usual side).
	Normal
	// Inverse sends with slot 1 and receives with slot 0 (--key-direction 1,
	// the client's usual side, and tls-crypt's fixed client direction).
	Inverse
)

// StaticKey is a parsed OpenVPN static key: the raw 256 bytes, from which the
// per-direction cipher and HMAC keys are sliced.
type StaticKey struct {
	raw [StaticKeyLen]byte
}

// ParseStaticKey reads an OpenVPN static key (the "-----BEGIN OpenVPN Static key
// V1-----" PEM-like format: 16 lines of 32 hex digits between the header and
// footer). It accepts the material inline or after stripping surrounding
// whitespace.
func ParseStaticKey(pem []byte) (*StaticKey, error) {
	var body strings.Builder
	inBody := false
	for line := range strings.SplitSeq(string(pem), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "":
			continue
		case strings.HasPrefix(line, "-----BEGIN"):
			inBody = true
		case strings.HasPrefix(line, "-----END"):
			inBody = false
		case inBody:
			body.WriteString(line)
		}
	}
	raw, err := hex.DecodeString(body.String())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadKey, err)
	}
	if len(raw) != StaticKeyLen {
		return nil, fmt.Errorf("%w: got %d bytes, want %d", ErrBadKey, len(raw), StaticKeyLen)
	}
	k := &StaticKey{}
	copy(k.raw[:], raw)
	return k, nil
}

// outSlot and inSlot report which of the two keys this direction sends and
// receives with.
func (d Direction) outSlot() int {
	if d == Inverse {
		return 1
	}
	return 0
}

func (d Direction) inSlot() int {
	switch d {
	case Normal:
		return 1
	case Inverse:
		return 0
	default: // Bidirectional
		return 0
	}
}

// key returns the 128-byte key struct at slot i.
func (k *StaticKey) key(slot int) []byte {
	return k.raw[slot*keyLen : (slot+1)*keyLen]
}

// hmacKey returns the HMAC key of the given slot, truncated to n octets (the
// digest size).
func (k *StaticKey) hmacKey(slot, n int) []byte {
	return k.key(slot)[hmacOff : hmacOff+n]
}

// cipherKey returns the cipher key of the given slot, truncated to n octets.
func (k *StaticKey) cipherKey(slot, n int) []byte {
	return k.key(slot)[cipherOff : cipherOff+n]
}
