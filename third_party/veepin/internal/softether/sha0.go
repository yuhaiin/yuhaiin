package softether

import (
	"encoding/binary"
	"math/bits"
)

// SHA-0 (FIPS 180, 1993), the withdrawn predecessor of SHA-1.
//
// SoftEther hashes every password with it, so a peer that wants to log in has
// to reproduce it. Go ships SHA-1 and not SHA-0, and the difference between
// them is one instruction: SHA-1 rotates the expanded message word left by one
// bit, SHA-0 does not.
//
//	SHA-1:  W[t] = ROTL1(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16])
//	SHA-0:  W[t] =       W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]
//
// That omission is why SHA-0 was withdrawn: it is the reason collisions were
// found against it years before SHA-1 fell. Nothing here depends on it being
// collision resistant — see the caveats in README.md — but it is the wire
// format, and the wire format is not ours to choose.
//
// It is deliberately unexported and package-local, the same treatment
// internal/ikev2/eap/md4.go gives MD4 for MSCHAPv2's NT hash: a legacy digest
// a protocol mandates, confined to the one corner that mandates it, rather
// than offered from internal/cryptoutil as though it were a choice a caller
// should be able to make.
//
// # Where this came from
//
// SoftEtherVPN/src/Mayaqua/Encrypt.c, MY_SHA0_Transform. The rotate is absent
// there in a way worth recording, because it reads as a bug and is not one:
//
//	//W[t] = rol(1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
//	W[t] = (1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
//
// The live line is a C comma expression. It evaluates 1, discards it, and
// yields the xor — so the rotate the commented-out line above it would have
// applied never happens, and the result is exactly SHA-0. Whether that was
// intended or was a rename that went one step too far, it is what every
// SoftEther server on the wire computes, so it is what this computes.

// sha0Size is the digest length in octets, the same 20 as SHA-1.
const sha0Size = 20

// sha0 returns the SHA-0 digest of data.
//
// The structure is SHA-1's, because SHA-0 *is* SHA-1 but for the message
// schedule: same initial state, same round constants, same four round
// functions at the same boundaries, same big-endian length padding.
func sha0(data []byte) [sha0Size]byte {
	h := [5]uint32{0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0}

	// Pad: 0x80, zeros to 56 mod 64, then the 64-bit big-endian bit length.
	padded := make([]byte, 0, len(data)+72)
	padded = append(padded, data...)
	padded = append(padded, 0x80)
	for len(padded)%64 != 56 {
		padded = append(padded, 0)
	}
	padded = binary.BigEndian.AppendUint64(padded, uint64(len(data))*8)

	var w [80]uint32
	for base := 0; base < len(padded); base += 64 {
		block := padded[base : base+64]
		for t := range 16 {
			w[t] = binary.BigEndian.Uint32(block[t*4:])
		}
		// The one line that makes this SHA-0 rather than SHA-1: no ROTL1.
		for t := 16; t < 80; t++ {
			w[t] = w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16]
		}

		a, b, c, d, e := h[0], h[1], h[2], h[3], h[4]
		for t := range 80 {
			var f, k uint32
			switch {
			case t < 20:
				f, k = d^(b&(c^d)), 0x5A827999
			case t < 40:
				f, k = b^c^d, 0x6ED9EBA1
			case t < 60:
				f, k = (b&c)|(d&(b|c)), 0x8F1BBCDC
			default:
				f, k = b^c^d, 0xCA62C1D6
			}
			tmp := bits.RotateLeft32(a, 5) + f + e + k + w[t]
			a, b, c, d, e = tmp, a, bits.RotateLeft32(b, 30), c, d
		}
		h[0] += a
		h[1] += b
		h[2] += c
		h[3] += d
		h[4] += e
	}

	var out [sha0Size]byte
	for i, v := range h {
		binary.BigEndian.PutUint32(out[i*4:], v)
	}
	return out
}
