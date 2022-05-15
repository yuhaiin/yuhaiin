// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// Package camellia implements the camellia block cipher.
// The cipher has block size of 128 bit (16 byte) and
// accepts 128, 192 or 256 bit keys (16, 24, 32 byte).
// Camellia was jointly developed by Mitsubishi Electric
// and NTT of Japan.
// Camellia was added to many crypto protocols (e.g. TLS).
package camellia

import (
	"crypto/cipher"
	"fmt"
)

// The block size of the camellia block cipher in bytes.
const BlockSize = 16

// from github.com/enceve/crypto/camellia/
// NewCipher returns a new cipher.Block implementing the camellia cipher.
// The key argument must be 128, 192 or 256 bit (16, 24, 32 byte).
func NewCipher(key []byte) (cipher.Block, error) {
	k := len(key)
	if k == 16 {
		c := new(blockCipher128)
		c.keySchedule(key)
		return c, nil
	}
	if k == 24 || k == 32 {
		c := new(blockCipher256)
		c.keySchedule(key)
		return c, nil
	}
	return nil, fmt.Errorf("key size error: %d", len(key))
}

// The camellia cipher for 128 bit keys.
type blockCipher128 struct {
	sk [52]uint32 // The 52 32-bit subkeys
}

func (c *blockCipher128) BlockSize() int { return BlockSize }

func (c *blockCipher128) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("camellia: src buffer to small")
	}
	if len(dst) < BlockSize {
		panic("camellia: dst buffer to small")
	}

	r0 := uint32(src[0])<<24 | uint32(src[1])<<16 | uint32(src[2])<<8 | uint32(src[3])
	r1 := uint32(src[4])<<24 | uint32(src[5])<<16 | uint32(src[6])<<8 | uint32(src[7])
	r2 := uint32(src[8])<<24 | uint32(src[9])<<16 | uint32(src[10])<<8 | uint32(src[11])
	r3 := uint32(src[12])<<24 | uint32(src[13])<<16 | uint32(src[14])<<8 | uint32(src[15])

	k := &(c.sk)

	r0 ^= k[0]
	r1 ^= k[1]
	r2 ^= k[2]
	r3 ^= k[3]

	f(&r0, &r1, &r2, &r3, k[4], k[5])
	f(&r2, &r3, &r0, &r1, k[6], k[7])
	f(&r0, &r1, &r2, &r3, k[8], k[9])
	f(&r2, &r3, &r0, &r1, k[10], k[11])
	f(&r0, &r1, &r2, &r3, k[12], k[13])
	f(&r2, &r3, &r0, &r1, k[14], k[15])

	t := r0 & k[16]
	r1 ^= (t << 1) | (t >> (32 - 1))
	r2 ^= r3 | k[19]
	r0 ^= r1 | k[17]
	t = r2 & k[18]
	r3 ^= (t << 1) | (t >> (32 - 1))

	f(&r0, &r1, &r2, &r3, k[20], k[21])
	f(&r2, &r3, &r0, &r1, k[22], k[23])
	f(&r0, &r1, &r2, &r3, k[24], k[25])
	f(&r2, &r3, &r0, &r1, k[26], k[27])
	f(&r0, &r1, &r2, &r3, k[28], k[29])
	f(&r2, &r3, &r0, &r1, k[30], k[31])

	t = r0 & k[32]
	r1 ^= (t << 1) | (t >> (32 - 1))
	r2 ^= r3 | k[35]
	r0 ^= r1 | k[33]
	t = r2 & k[34]
	r3 ^= (t << 1) | (t >> (32 - 1))

	f(&r0, &r1, &r2, &r3, k[36], k[37])
	f(&r2, &r3, &r0, &r1, k[38], k[39])
	f(&r0, &r1, &r2, &r3, k[40], k[41])
	f(&r2, &r3, &r0, &r1, k[42], k[43])
	f(&r0, &r1, &r2, &r3, k[44], k[45])
	f(&r2, &r3, &r0, &r1, k[46], k[47])

	r2 ^= k[48]
	r3 ^= k[49]
	r0 ^= k[50]
	r1 ^= k[51]

	dst[0] = byte(r2 >> 24)
	dst[1] = byte(r2 >> 16)
	dst[2] = byte(r2 >> 8)
	dst[3] = byte(r2)
	dst[4] = byte(r3 >> 24)
	dst[5] = byte(r3 >> 16)
	dst[6] = byte(r3 >> 8)
	dst[7] = byte(r3)
	dst[8] = byte(r0 >> 24)
	dst[9] = byte(r0 >> 16)
	dst[10] = byte(r0 >> 8)
	dst[11] = byte(r0)
	dst[12] = byte(r1 >> 24)
	dst[13] = byte(r1 >> 16)
	dst[14] = byte(r1 >> 8)
	dst[15] = byte(r1)
}

func (c *blockCipher128) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("camellia: src buffer to small")
	}
	if len(dst) < BlockSize {
		panic("camellia: dst buffer to small")
	}

	r0 := uint32(src[0])<<24 | uint32(src[1])<<16 | uint32(src[2])<<8 | uint32(src[3])
	r1 := uint32(src[4])<<24 | uint32(src[5])<<16 | uint32(src[6])<<8 | uint32(src[7])
	r2 := uint32(src[8])<<24 | uint32(src[9])<<16 | uint32(src[10])<<8 | uint32(src[11])
	r3 := uint32(src[12])<<24 | uint32(src[13])<<16 | uint32(src[14])<<8 | uint32(src[15])

	k := &(c.sk)

	r3 ^= k[51]
	r2 ^= k[50]
	r1 ^= k[49]
	r0 ^= k[48]

	f(&r0, &r1, &r2, &r3, k[46], k[47])
	f(&r2, &r3, &r0, &r1, k[44], k[45])
	f(&r0, &r1, &r2, &r3, k[42], k[43])
	f(&r2, &r3, &r0, &r1, k[40], k[41])
	f(&r0, &r1, &r2, &r3, k[38], k[39])
	f(&r2, &r3, &r0, &r1, k[36], k[37])

	t := r0 & k[34]
	r1 ^= (t << 1) | (t >> (32 - 1))
	r2 ^= r3 | k[33]
	r0 ^= r1 | k[35]
	t = r2 & k[32]
	r3 ^= (t << 1) | (t >> (32 - 1))

	f(&r0, &r1, &r2, &r3, k[30], k[31])
	f(&r2, &r3, &r0, &r1, k[28], k[29])
	f(&r0, &r1, &r2, &r3, k[26], k[27])
	f(&r2, &r3, &r0, &r1, k[24], k[25])
	f(&r0, &r1, &r2, &r3, k[22], k[23])
	f(&r2, &r3, &r0, &r1, k[20], k[21])

	t = r0 & k[18]
	r1 ^= (t << 1) | (t >> (32 - 1))
	r2 ^= r3 | k[17]
	r0 ^= r1 | k[19]
	t = r2 & k[16]
	r3 ^= (t << 1) | (t >> (32 - 1))

	f(&r0, &r1, &r2, &r3, k[14], k[15])
	f(&r2, &r3, &r0, &r1, k[12], k[13])
	f(&r0, &r1, &r2, &r3, k[10], k[11])
	f(&r2, &r3, &r0, &r1, k[8], k[9])
	f(&r0, &r1, &r2, &r3, k[6], k[7])
	f(&r2, &r3, &r0, &r1, k[4], k[5])

	r1 ^= k[3]
	r0 ^= k[2]
	r3 ^= k[1]
	r2 ^= k[0]

	dst[0] = byte(r2 >> 24)
	dst[1] = byte(r2 >> 16)
	dst[2] = byte(r2 >> 8)
	dst[3] = byte(r2)
	dst[4] = byte(r3 >> 24)
	dst[5] = byte(r3 >> 16)
	dst[6] = byte(r3 >> 8)
	dst[7] = byte(r3)
	dst[8] = byte(r0 >> 24)
	dst[9] = byte(r0 >> 16)
	dst[10] = byte(r0 >> 8)
	dst[11] = byte(r0)
	dst[12] = byte(r1 >> 24)
	dst[13] = byte(r1 >> 16)
	dst[14] = byte(r1 >> 8)
	dst[15] = byte(r1)
}

// The camellia cipher for 192 or 256 bit keys.
type blockCipher256 struct {
	sk [68]uint32 // The 68 32-bit subkeys
}

func (c *blockCipher256) BlockSize() int { return BlockSize }

func (c *blockCipher256) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("camellia: src buffer to small")
	}
	if len(dst) < BlockSize {
		panic("camellia: dst buffer to small")
	}

	r0 := uint32(src[0])<<24 | uint32(src[1])<<16 | uint32(src[2])<<8 | uint32(src[3])
	r1 := uint32(src[4])<<24 | uint32(src[5])<<16 | uint32(src[6])<<8 | uint32(src[7])
	r2 := uint32(src[8])<<24 | uint32(src[9])<<16 | uint32(src[10])<<8 | uint32(src[11])
	r3 := uint32(src[12])<<24 | uint32(src[13])<<16 | uint32(src[14])<<8 | uint32(src[15])

	k := &(c.sk)

	r0 ^= k[0]
	r1 ^= k[1]
	r2 ^= k[2]
	r3 ^= k[3]

	f(&r0, &r1, &r2, &r3, k[4], k[5])
	f(&r2, &r3, &r0, &r1, k[6], k[7])
	f(&r0, &r1, &r2, &r3, k[8], k[9])
	f(&r2, &r3, &r0, &r1, k[10], k[11])
	f(&r0, &r1, &r2, &r3, k[12], k[13])
	f(&r2, &r3, &r0, &r1, k[14], k[15])

	t := r0 & k[16]
	r1 ^= (t << 1) | (t >> (32 - 1))
	r2 ^= r3 | k[19]
	r0 ^= r1 | k[17]
	t = r2 & k[18]
	r3 ^= (t << 1) | (t >> (32 - 1))

	f(&r0, &r1, &r2, &r3, k[20], k[21])
	f(&r2, &r3, &r0, &r1, k[22], k[23])
	f(&r0, &r1, &r2, &r3, k[24], k[25])
	f(&r2, &r3, &r0, &r1, k[26], k[27])
	f(&r0, &r1, &r2, &r3, k[28], k[29])
	f(&r2, &r3, &r0, &r1, k[30], k[31])

	t = r0 & k[32]
	r1 ^= (t << 1) | (t >> (32 - 1))
	r2 ^= r3 | k[35]
	r0 ^= r1 | k[33]
	t = r2 & k[34]
	r3 ^= (t << 1) | (t >> (32 - 1))

	f(&r0, &r1, &r2, &r3, k[36], k[37])
	f(&r2, &r3, &r0, &r1, k[38], k[39])
	f(&r0, &r1, &r2, &r3, k[40], k[41])
	f(&r2, &r3, &r0, &r1, k[42], k[43])
	f(&r0, &r1, &r2, &r3, k[44], k[45])
	f(&r2, &r3, &r0, &r1, k[46], k[47])

	t = r0 & k[48]
	r1 ^= (t << 1) | (t >> (32 - 1))
	r2 ^= r3 | k[51]
	r0 ^= r1 | k[49]
	t = r2 & k[50]
	r3 ^= (t << 1) | (t >> (32 - 1))

	f(&r0, &r1, &r2, &r3, k[52], k[53])
	f(&r2, &r3, &r0, &r1, k[54], k[55])
	f(&r0, &r1, &r2, &r3, k[56], k[57])
	f(&r2, &r3, &r0, &r1, k[58], k[59])
	f(&r0, &r1, &r2, &r3, k[60], k[61])
	f(&r2, &r3, &r0, &r1, k[62], k[63])

	r2 ^= c.sk[64]
	r3 ^= c.sk[65]
	r0 ^= c.sk[66]
	r1 ^= c.sk[67]

	dst[0] = byte(r2 >> 24)
	dst[1] = byte(r2 >> 16)
	dst[2] = byte(r2 >> 8)
	dst[3] = byte(r2)
	dst[4] = byte(r3 >> 24)
	dst[5] = byte(r3 >> 16)
	dst[6] = byte(r3 >> 8)
	dst[7] = byte(r3)
	dst[8] = byte(r0 >> 24)
	dst[9] = byte(r0 >> 16)
	dst[10] = byte(r0 >> 8)
	dst[11] = byte(r0)
	dst[12] = byte(r1 >> 24)
	dst[13] = byte(r1 >> 16)
	dst[14] = byte(r1 >> 8)
	dst[15] = byte(r1)
}

func (c *blockCipher256) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("camellia: src buffer to small")
	}
	if len(dst) < BlockSize {
		panic("camellia: dst buffer to small")
	}

	r0 := uint32(src[0])<<24 | uint32(src[1])<<16 | uint32(src[2])<<8 | uint32(src[3])
	r1 := uint32(src[4])<<24 | uint32(src[5])<<16 | uint32(src[6])<<8 | uint32(src[7])
	r2 := uint32(src[8])<<24 | uint32(src[9])<<16 | uint32(src[10])<<8 | uint32(src[11])
	r3 := uint32(src[12])<<24 | uint32(src[13])<<16 | uint32(src[14])<<8 | uint32(src[15])

	k := &(c.sk)

	r3 ^= k[67]
	r2 ^= k[66]
	r1 ^= k[65]
	r0 ^= k[64]

	f(&r0, &r1, &r2, &r3, k[62], k[63])
	f(&r2, &r3, &r0, &r1, k[60], k[61])
	f(&r0, &r1, &r2, &r3, k[58], k[59])
	f(&r2, &r3, &r0, &r1, k[56], k[57])
	f(&r0, &r1, &r2, &r3, k[54], k[55])
	f(&r2, &r3, &r0, &r1, k[52], k[53])

	t := r0 & k[50]
	r1 ^= (t << 1) | (t >> (32 - 1))
	r2 ^= r3 | k[49]
	r0 ^= r1 | k[51]
	t = r2 & k[48]
	r3 ^= (t << 1) | (t >> (32 - 1))

	f(&r0, &r1, &r2, &r3, k[46], k[47])
	f(&r2, &r3, &r0, &r1, k[44], k[45])
	f(&r0, &r1, &r2, &r3, k[42], k[43])
	f(&r2, &r3, &r0, &r1, k[40], k[41])
	f(&r0, &r1, &r2, &r3, k[38], k[39])
	f(&r2, &r3, &r0, &r1, k[36], k[37])

	t = r0 & k[34]
	r1 ^= (t << 1) | (t >> (32 - 1))
	r2 ^= r3 | k[33]
	r0 ^= r1 | k[35]
	t = r2 & k[32]
	r3 ^= (t << 1) | (t >> (32 - 1))

	f(&r0, &r1, &r2, &r3, k[30], k[31])
	f(&r2, &r3, &r0, &r1, k[28], k[29])
	f(&r0, &r1, &r2, &r3, k[26], k[27])
	f(&r2, &r3, &r0, &r1, k[24], k[25])
	f(&r0, &r1, &r2, &r3, k[22], k[23])
	f(&r2, &r3, &r0, &r1, k[20], k[21])

	t = r0 & k[18]
	r1 ^= (t << 1) | (t >> (32 - 1))
	r2 ^= r3 | k[17]
	r0 ^= r1 | k[19]
	t = r2 & k[16]
	r3 ^= (t << 1) | (t >> (32 - 1))

	f(&r0, &r1, &r2, &r3, k[14], k[15])
	f(&r2, &r3, &r0, &r1, k[12], k[13])
	f(&r0, &r1, &r2, &r3, k[10], k[11])
	f(&r2, &r3, &r0, &r1, k[8], k[9])
	f(&r0, &r1, &r2, &r3, k[6], k[7])
	f(&r2, &r3, &r0, &r1, k[4], k[5])

	r1 ^= k[3]
	r0 ^= k[2]
	r3 ^= k[1]
	r2 ^= k[0]

	dst[0] = byte(r2 >> 24)
	dst[1] = byte(r2 >> 16)
	dst[2] = byte(r2 >> 8)
	dst[3] = byte(r2)
	dst[4] = byte(r3 >> 24)
	dst[5] = byte(r3 >> 16)
	dst[6] = byte(r3 >> 8)
	dst[7] = byte(r3)
	dst[8] = byte(r0 >> 24)
	dst[9] = byte(r0 >> 16)
	dst[10] = byte(r0 >> 8)
	dst[11] = byte(r0)
	dst[12] = byte(r1 >> 24)
	dst[13] = byte(r1 >> 16)
	dst[14] = byte(r1 >> 8)
	dst[15] = byte(r1)
}

// The camellia key schedule for 128 bit keys.
func (c *blockCipher128) keySchedule(key []byte) {
	r0 := uint32(key[0])<<24 | uint32(key[1])<<16 | uint32(key[2])<<8 | uint32(key[3])
	r1 := uint32(key[4])<<24 | uint32(key[5])<<16 | uint32(key[6])<<8 | uint32(key[7])
	r2 := uint32(key[8])<<24 | uint32(key[9])<<16 | uint32(key[10])<<8 | uint32(key[11])
	r3 := uint32(key[12])<<24 | uint32(key[13])<<16 | uint32(key[14])<<8 | uint32(key[15])

	k := &(c.sk)

	k[0], k[1], k[2], k[3] = r0, r1, r2, r3

	f(&r0, &r1, &r2, &r3, sigma[0], sigma[1])
	f(&r2, &r3, &r0, &r1, sigma[2], sigma[3])

	r0 ^= k[0]
	r1 ^= k[1]
	r2 ^= k[2]
	r3 ^= k[3]
	f(&r0, &r1, &r2, &r3, sigma[4], sigma[5])
	f(&r2, &r3, &r0, &r1, sigma[6], sigma[7])

	k[4], k[5], k[6], k[7] = r0, r1, r2, r3
	rotl128(&r0, &r1, &r2, &r3, 15) // KA <<< 15
	k[12], k[13], k[14], k[15] = r0, r1, r2, r3
	rotl128(&r0, &r1, &r2, &r3, 15) // KA <<< 30
	k[16], k[17], k[18], k[19] = r0, r1, r2, r3
	rotl128(&r0, &r1, &r2, &r3, 15) // KA <<< 45
	k[24] = r0
	k[25] = r1
	rotl128(&r0, &r1, &r2, &r3, 15) // KA <<< 60
	k[28], k[29], k[30], k[31] = r0, r1, r2, r3
	rotl128(&r1, &r2, &r3, &r0, 2) // KA <<< 94
	k[40], k[41], k[42], k[43] = r1, r2, r3, r0
	rotl128(&r1, &r2, &r3, &r0, 17) // KA <<<111
	k[48], k[49], k[50], k[51] = r1, r2, r3, r0

	r0, r1, r2, r3 = k[0], k[1], k[2], k[3]
	rotl128(&r0, &r1, &r2, &r3, 15) // KL <<< 15
	k[8], k[9], k[10], k[11] = r0, r1, r2, r3
	rotl128(&r0, &r1, &r2, &r3, 30) // KL <<< 45
	k[20], k[21], k[22], k[23] = r0, r1, r2, r3
	rotl128(&r0, &r1, &r2, &r3, 15) // KL <<< 60
	k[26] = r2
	k[27] = r3
	rotl128(&r0, &r1, &r2, &r3, 17) // KL <<< 77
	k[32], k[33], k[34], k[35] = r0, r1, r2, r3
	rotl128(&r0, &r1, &r2, &r3, 17) // KL <<< 94
	k[36], k[37], k[38], k[39] = r0, r1, r2, r3
	rotl128(&r0, &r1, &r2, &r3, 17) // KL <<<111
	k[44], k[45], k[46], k[47] = r0, r1, r2, r3
}

// The camellia key schedule for 192 or 256 bit keys.
func (c *blockCipher256) keySchedule(key []byte) {
	k := &(c.sk)
	k[0] = uint32(key[0])<<24 | uint32(key[1])<<16 | uint32(key[2])<<8 | uint32(key[3])
	k[1] = uint32(key[4])<<24 | uint32(key[5])<<16 | uint32(key[6])<<8 | uint32(key[7])
	k[2] = uint32(key[8])<<24 | uint32(key[9])<<16 | uint32(key[10])<<8 | uint32(key[11])
	k[3] = uint32(key[12])<<24 | uint32(key[13])<<16 | uint32(key[14])<<8 | uint32(key[15])

	k[8] = uint32(key[16])<<24 | uint32(key[17])<<16 | uint32(key[18])<<8 | uint32(key[19])
	k[9] = uint32(key[20])<<24 | uint32(key[21])<<16 | uint32(key[22])<<8 | uint32(key[23])
	if len(key) == 24 {
		k[10] = ^k[8]
		k[11] = ^k[9]
	} else {
		k[10] = uint32(key[24])<<24 | uint32(key[25])<<16 | uint32(key[26])<<8 | uint32(key[27])
		k[11] = uint32(key[28])<<24 | uint32(key[29])<<16 | uint32(key[30])<<8 | uint32(key[31])
	}

	s0 := k[8] ^ k[0]
	s1 := k[9] ^ k[1]
	s2 := k[10] ^ k[2]
	s3 := k[11] ^ k[3]

	f(&s0, &s1, &s2, &s3, sigma[0], sigma[1])
	f(&s2, &s3, &s0, &s1, sigma[2], sigma[3])

	s0 ^= k[0]
	s1 ^= k[1]
	s2 ^= k[2]
	s3 ^= k[3]
	f(&s0, &s1, &s2, &s3, sigma[4], sigma[5])
	f(&s2, &s3, &s0, &s1, sigma[6], sigma[7])

	k[12], k[13], k[14], k[15] = s0, s1, s2, s3
	s0 ^= k[8]
	s1 ^= k[9]
	s2 ^= k[10]
	s3 ^= k[11]
	f(&s0, &s1, &s2, &s3, sigma[8], sigma[9])
	f(&s2, &s3, &s0, &s1, sigma[10], sigma[11])

	k[4], k[5], k[6], k[7] = s0, s1, s2, s3
	rotl128(&s0, &s1, &s2, &s3, 30) // KB <<< 30
	k[20], k[21], k[22], k[23] = s0, s1, s2, s3
	rotl128(&s0, &s1, &s2, &s3, 30) // KB <<< 60
	k[40], k[41], k[42], k[43] = s0, s1, s2, s3
	rotl128(&s1, &s2, &s3, &s0, 19) // KB <<<111
	k[64], k[65], k[66], k[67] = s1, s2, s3, s0

	s0, s1, s2, s3 = k[8], k[9], k[10], k[11]
	rotl128(&s0, &s1, &s2, &s3, 15) // KR <<< 15
	k[8], k[9], k[10], k[11] = s0, s1, s2, s3
	rotl128(&s0, &s1, &s2, &s3, 15) // KR <<< 30
	k[16], k[17], k[18], k[19] = s0, s1, s2, s3
	rotl128(&s0, &s1, &s2, &s3, 30) // KR <<< 60
	k[36], k[37], k[38], k[39] = s0, s1, s2, s3
	rotl128(&s1, &s2, &s3, &s0, 2) // KR <<< 94
	k[52], k[53], k[54], k[55] = s1, s2, s3, s0

	s0, s1, s2, s3 = k[12], k[13], k[14], k[15]
	rotl128(&s0, &s1, &s2, &s3, 15) // KA <<< 15
	k[12], k[13], k[14], k[15] = s0, s1, s2, s3
	rotl128(&s0, &s1, &s2, &s3, 30) // KA <<< 45
	k[28], k[29], k[30], k[31] = s0, s1, s2, s3
	// KA <<< 77
	k[48], k[49], k[50], k[51] = s1, s2, s3, s0
	rotl128(&s1, &s2, &s3, &s0, 17) // KA <<< 94
	k[56], k[57], k[58], k[59] = s1, s2, s3, s0

	s0, s1, s2, s3 = k[0], k[1], k[2], k[3]
	rotl128(&s1, &s2, &s3, &s0, 13) // KL <<< 45
	k[24], k[25], k[26], k[27] = s1, s2, s3, s0
	rotl128(&s1, &s2, &s3, &s0, 15) // KL <<< 60
	k[32], k[33], k[34], k[35] = s1, s2, s3, s0
	rotl128(&s1, &s2, &s3, &s0, 17) // KL <<< 77
	k[44], k[45], k[46], k[47] = s1, s2, s3, s0
	rotl128(&s2, &s3, &s0, &s1, 2) // KL <<<111
	k[60], k[61], k[62], k[63] = s2, s3, s0, s1
}
