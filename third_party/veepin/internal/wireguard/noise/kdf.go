package noise

import (
	"crypto/hmac"
	"hash"

	"github.com/xen0bit/veepin/internal/cryptoutil"
)

// The three primitives WireGuard names in its construction string
// (Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s), spelled out here so the handshake
// reads like the protocol paper:
//
//	HASH = BLAKE2s-256, unkeyed
//	MAC  = BLAKE2s-128, keyed        (mac1, mac2, cookie — 128 bits, not 256)
//	HMAC = HMAC with BLAKE2s-256     (the KDF's underlying PRF)
//
// HMAC is the standard construction over the *unkeyed* hash; BLAKE2's own keyed
// mode is a different function and is used only for MAC.

// hashSize is the BLAKE2s-256 digest length, which is also the chaining key,
// hash, and every derived key's length.
const hashSize = cryptoutil.BLAKE2sSize

type key = [hashSize]byte

// hashOf returns HASH(parts...) — BLAKE2s-256 over the concatenation.
func hashOf(parts ...[]byte) key {
	h := cryptoutil.NewBLAKE2s()
	for _, p := range parts {
		h.Write(p)
	}
	var out key
	copy(out[:], h.Sum(nil))
	return out
}

// newHMAC returns HMAC-BLAKE2s-256 keyed with k.
func newHMAC(k []byte) hash.Hash {
	return hmac.New(func() hash.Hash { return cryptoutil.NewBLAKE2s() }, k)
}

// mac128 returns MAC(k, data): keyed BLAKE2s-128, WireGuard's mac1/mac2/cookie.
func mac128(k, data []byte) [cryptoutil.BLAKE2s128Size]byte {
	h, err := cryptoutil.NewBLAKE2s128MAC(k)
	if err != nil {
		// Only a key longer than 32 octets can fail, and every caller passes a
		// 32-octet digest, so this is a programming error rather than input.
		panic("noise: BLAKE2s-128 MAC: " + err.Error())
	}
	h.Write(data)
	var out [cryptoutil.BLAKE2s128Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

// hmacSum returns HMAC(k, parts...).
func hmacSum(k []byte, parts ...[]byte) key {
	h := newHMAC(k)
	for _, p := range parts {
		h.Write(p)
	}
	var out key
	copy(out[:], h.Sum(nil))
	return out
}

// The KDF (protocol paper §5.4). Each output is an HMAC chained off a temporary
// key, with a counter byte distinguishing them:
//
//	temp    = HMAC(chaining_key, input)
//	output1 = HMAC(temp, 0x1)
//	output2 = HMAC(temp, output1 || 0x2)
//	output3 = HMAC(temp, output2 || 0x3)
//
// kdf1/kdf2/kdf3 return as many outputs as the step needs. Splitting them this
// way keeps the handshake free of unused values, which is what makes a misplaced
// KDF call fail to compile rather than derive a wrong key silently.

func kdf1(ck *key, input []byte) key {
	temp := hmacSum(ck[:], input)
	return hmacSum(temp[:], []byte{0x1})
}

func kdf2(ck *key, input []byte) (key, key) {
	temp := hmacSum(ck[:], input)
	out1 := hmacSum(temp[:], []byte{0x1})
	out2 := hmacSum(temp[:], out1[:], []byte{0x2})
	return out1, out2
}

func kdf3(ck *key, input []byte) (key, key, key) {
	temp := hmacSum(ck[:], input)
	out1 := hmacSum(temp[:], []byte{0x1})
	out2 := hmacSum(temp[:], out1[:], []byte{0x2})
	out3 := hmacSum(temp[:], out2[:], []byte{0x3})
	return out1, out2, out3
}
