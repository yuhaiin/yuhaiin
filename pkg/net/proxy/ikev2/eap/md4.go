// Package eap implements the minimal EAP machinery needed for IKEv2
// username/password authentication: the EAP packet format (RFC 3748) and the
// EAP-MSCHAPv2 method (RFC 2759 / RFC 3079).
//
// MSCHAPv2 depends on the MD4 digest for NT password hashing. MD4 is not in the
// Go standard library, so a compact implementation (RFC 1320) is included here
// to keep the module dependency-free. MD4 is used only for the legacy NT hash
// construction that the protocol mandates; it is not used as a general-purpose
// hash.
package eap

// md4 computes the RFC 1320 MD4 digest of data.
func md4(data []byte) [16]byte {
	var a uint32 = 0x67452301
	var b uint32 = 0xefcdab89
	var c uint32 = 0x98badcfe
	var d uint32 = 0x10325476

	// Pad the message: append 0x80, then zeros, then the 64-bit bit length.
	msgLen := len(data)
	padded := make([]byte, 0, msgLen+72)
	padded = append(padded, data...)
	padded = append(padded, 0x80)
	for len(padded)%64 != 56 {
		padded = append(padded, 0)
	}
	bitLen := uint64(msgLen) * 8
	for i := 0; i < 8; i++ {
		padded = append(padded, byte(bitLen>>(8*uint(i))))
	}

	rol := func(x uint32, s uint) uint32 { return x<<s | x>>(32-s) }

	for off := 0; off < len(padded); off += 64 {
		var x [16]uint32
		for i := 0; i < 16; i++ {
			j := off + i*4
			x[i] = uint32(padded[j]) | uint32(padded[j+1])<<8 |
				uint32(padded[j+2])<<16 | uint32(padded[j+3])<<24
		}
		aa, bb, cc, dd := a, b, c, d

		// Round 1.
		ff := func(x, y, z uint32) uint32 { return (x & y) | (^x & z) }
		r1 := func(a, b, c, d, k uint32, s uint) uint32 {
			return rol(a+ff(b, c, d)+x[k], s)
		}
		a = r1(a, b, c, d, 0, 3)
		d = r1(d, a, b, c, 1, 7)
		c = r1(c, d, a, b, 2, 11)
		b = r1(b, c, d, a, 3, 19)
		a = r1(a, b, c, d, 4, 3)
		d = r1(d, a, b, c, 5, 7)
		c = r1(c, d, a, b, 6, 11)
		b = r1(b, c, d, a, 7, 19)
		a = r1(a, b, c, d, 8, 3)
		d = r1(d, a, b, c, 9, 7)
		c = r1(c, d, a, b, 10, 11)
		b = r1(b, c, d, a, 11, 19)
		a = r1(a, b, c, d, 12, 3)
		d = r1(d, a, b, c, 13, 7)
		c = r1(c, d, a, b, 14, 11)
		b = r1(b, c, d, a, 15, 19)

		// Round 2.
		gg := func(x, y, z uint32) uint32 { return (x & y) | (x & z) | (y & z) }
		r2 := func(a, b, c, d, k uint32, s uint) uint32 {
			return rol(a+gg(b, c, d)+x[k]+0x5a827999, s)
		}
		a = r2(a, b, c, d, 0, 3)
		d = r2(d, a, b, c, 4, 5)
		c = r2(c, d, a, b, 8, 9)
		b = r2(b, c, d, a, 12, 13)
		a = r2(a, b, c, d, 1, 3)
		d = r2(d, a, b, c, 5, 5)
		c = r2(c, d, a, b, 9, 9)
		b = r2(b, c, d, a, 13, 13)
		a = r2(a, b, c, d, 2, 3)
		d = r2(d, a, b, c, 6, 5)
		c = r2(c, d, a, b, 10, 9)
		b = r2(b, c, d, a, 14, 13)
		a = r2(a, b, c, d, 3, 3)
		d = r2(d, a, b, c, 7, 5)
		c = r2(c, d, a, b, 11, 9)
		b = r2(b, c, d, a, 15, 13)

		// Round 3.
		hh := func(x, y, z uint32) uint32 { return x ^ y ^ z }
		r3 := func(a, b, c, d, k uint32, s uint) uint32 {
			return rol(a+hh(b, c, d)+x[k]+0x6ed9eba1, s)
		}
		a = r3(a, b, c, d, 0, 3)
		d = r3(d, a, b, c, 8, 9)
		c = r3(c, d, a, b, 4, 11)
		b = r3(b, c, d, a, 12, 15)
		a = r3(a, b, c, d, 2, 3)
		d = r3(d, a, b, c, 10, 9)
		c = r3(c, d, a, b, 6, 11)
		b = r3(b, c, d, a, 14, 15)
		a = r3(a, b, c, d, 1, 3)
		d = r3(d, a, b, c, 9, 9)
		c = r3(c, d, a, b, 5, 11)
		b = r3(b, c, d, a, 13, 15)
		a = r3(a, b, c, d, 3, 3)
		d = r3(d, a, b, c, 11, 9)
		c = r3(c, d, a, b, 7, 11)
		b = r3(b, c, d, a, 15, 15)

		a += aa
		b += bb
		c += cc
		d += dd
	}

	var out [16]byte
	for i, v := range []uint32{a, b, c, d} {
		out[i*4] = byte(v)
		out[i*4+1] = byte(v >> 8)
		out[i*4+2] = byte(v >> 16)
		out[i*4+3] = byte(v >> 24)
	}
	return out
}
