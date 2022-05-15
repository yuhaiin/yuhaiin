// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package camellia

// The camellia non-linear feistel function.
func f(r0, r1, r2, r3 *uint32, k0, k1 uint32) {
	k0 ^= *r0
	k1 ^= *r1

	t := sbox4_4404[byte(k0)]
	t ^= sbox3_3033[byte(k0>>8)]
	t ^= sbox2_0222[byte(k0>>16)]
	t ^= sbox1_1110[byte(k0>>24)]
	*r3 ^= (t >> 8) | (t << (32 - 8))

	k0 = t
	k0 ^= sbox1_1110[byte(k1)]
	k0 ^= sbox4_4404[byte(k1>>8)]
	k0 ^= sbox3_3033[byte(k1>>16)]
	k0 ^= sbox2_0222[byte(k1>>24)]

	*r2 ^= k0
	*r3 ^= k0
}

// Note that n has to be less than 32. Rotations for larger amount
// of bits are achieved by "rotating" order of registers and
// adjusting n accordingly, e.g. RotLeft128(r1,r2,r3,r0,n-32).
func rotl128(r0, r1, r2, r3 *uint32, n uint) {
	t := *r0 >> (32 - n)
	*r0 = (*r0 << n) | (*r1 >> (32 - n))
	*r1 = (*r1 << n) | (*r2 >> (32 - n))
	*r2 = (*r2 << n) | (*r3 >> (32 - n))
	*r3 = (*r3 << n) | t
}
