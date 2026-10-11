package toy

// The deliberately-worthless "cryptography".
//
// Every function in this file is a placeholder standing where a real primitive
// belongs, chosen so a reader can see the *role* each one plays without having
// to follow a real construction. SPEC.md enumerates the ways they fail; the
// short version:
//
//   - the keystream is a 32-octet repeating pad, so XORing two ciphertexts
//     cancels it and leaves the XOR of two plaintexts;
//   - FNV-1a is a hash-table hash, not a MAC, and forging a tag is arithmetic
//     rather than search;
//   - the key is a function of a long-term secret and two public nonces, so
//     there is no forward secrecy and an observer can derive it.
//
// The structure around them is worth copying: authenticate the framing as well
// as the payload, check the tag before touching any state, derive per-direction
// keys from both sides' contributions. Those habits are what a real protocol
// keeps; the primitives are what it replaces.

import (
	"crypto/subtle"
	"encoding/binary"
)

// FNV-1a 64-bit parameters. Chosen because it is four lines in any language,
// which is what makes SPEC.md reimplementable.
const (
	fnvOffset uint64 = 0xcbf29ce484222325
	fnvPrime  uint64 = 0x100000001b3
)

// digest is the one hash TOY uses, for key derivation, the auth proof and the
// packet tag alike. A real protocol would use three different, purpose-built
// constructions here.
func digest(parts ...[]byte) [TagLen]byte {
	h := fnvOffset
	for _, p := range parts {
		for _, b := range p {
			h ^= uint64(b)
			h *= fnvPrime
		}
	}
	var out [TagLen]byte
	binary.BigEndian.PutUint64(out[:], h)
	return out
}

// Key is the derived session key, shared by both directions.
type Key [KeyLen]byte

// DeriveKey computes the session key from the shared secret and both nonces.
//
// Both sides compute this independently and nothing is transmitted, which is
// the one property here that matches how a real protocol works. Everything else
// about it is wrong: with no ephemeral key exchange, the key is a pure function
// of a long-term secret and two values that travelled in the clear, so an
// observer who later learns the secret can decrypt every session they recorded.
func DeriveKey(secret string, clientNonce, serverNonce []byte) Key {
	var k Key
	for i := range 4 {
		block := digest([]byte(secret), clientNonce, serverNonce, []byte{byte(i)})
		copy(k[i*TagLen:], block[:])
	}
	return k
}

// Proof is the value the client sends to show it knows the secret.
func Proof(secret string, clientNonce, serverNonce []byte) [TagLen]byte {
	return digest([]byte(secret), clientNonce, serverNonce, []byte("toy-auth"))
}

// CheckProof compares a received proof against the expected one.
//
// The comparison is constant-time. It does not matter here — the whole scheme
// is broken by inspection — but a timing-variable compare in an authentication
// path is exactly the habit this example should not teach.
func CheckProof(secret string, clientNonce, serverNonce, got []byte) bool {
	want := Proof(secret, clientNonce, serverNonce)
	return subtle.ConstantTimeCompare(want[:], got) == 1
}

// Keystream applies the XOR pad in place, for the given counter.
//
// XOR is its own inverse, so this is both the encrypt and the decrypt path --
// which is convenient, and is also a hint that nothing of value is happening.
func Keystream(k Key, counter uint32, buf []byte) {
	for i := range buf {
		pad := k[(i+int(counter))%KeyLen]
		pad ^= byte(counter >> (8 * (i % 4)))
		buf[i] ^= pad
	}
}

// Tag authenticates a packet: the key, the header, and the ciphertext.
//
// Covering the header is the part worth copying. It means the type, session and
// counter cannot be edited in flight without invalidating the tag, so a
// receiver can trust the framing it just used to route the packet. A real
// protocol gets this by passing the header to an AEAD as additional data.
func Tag(k Key, header, ciphertext []byte) [TagLen]byte {
	return digest(k[:], header, ciphertext)
}

// CheckTag verifies a packet tag in constant time.
func CheckTag(k Key, header, ciphertext, got []byte) bool {
	want := Tag(k, header, ciphertext)
	return subtle.ConstantTimeCompare(want[:], got) == 1
}
