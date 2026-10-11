package cryptoutil

import (
	"crypto/hmac"
	"hash"
)

// PRF is a keyed pseudorandom function (RFC 7296 section 2.13).
type PRF struct {
	newMAC func(key []byte) hash.Hash
	Size   int // output length in bytes
	// PreferredKeyLen is the key length used when the PRF key is variable and
	// we are choosing one (equal to the output size for HMAC PRFs).
	PreferredKeyLen int
}

// NewHMACPRF builds an HMAC-based PRF over the given hash. For HMAC PRFs the
// preferred key length equals the hash output size (RFC 7296 section 2.13).
func NewHMACPRF(newHash func() hash.Hash) *PRF {
	size := newHash().Size()
	return &PRF{
		newMAC:          func(k []byte) hash.Hash { return hmac.New(newHash, k) },
		Size:            size,
		PreferredKeyLen: size,
	}
}

// Apply computes prf(key, data).
func (p *PRF) Apply(key, data []byte) []byte {
	m := p.newMAC(key)
	m.Write(data)
	return m.Sum(nil)
}

// Plus implements prf+ (RFC 7296 section 2.13):
//
//	prf+(K,S) = T1 | T2 | T3 | ...
//	T1 = prf(K, S | 0x01)
//	Tn = prf(K, Tn-1 | S | n)
//
// It returns exactly n bytes.
func (p *PRF) Plus(key, seed []byte, n int) []byte {
	out := make([]byte, 0, n)
	mac := p.newMAC(key) // reused across iterations via Reset
	var prev []byte
	var cb [1]byte
	var sumBuf [64]byte // large enough for any supported PRF output
	for counter := byte(1); len(out) < n; counter++ {
		mac.Reset()
		mac.Write(prev)
		mac.Write(seed)
		cb[0] = counter
		mac.Write(cb[:])
		prev = mac.Sum(sumBuf[:0])
		out = append(out, prev...)
	}
	return out[:n]
}

// Integrity is a MAC transform used by non-AEAD SK ciphers (RFC 7296 2.14).
type Integrity struct {
	newMAC func(key []byte) hash.Hash
	KeyLen int // key length in bytes
	ICVLen int // truncated output length in bytes
}

// NewHMACIntegrity builds an HMAC integrity transform over the given hash,
// truncating its output to icvLen octets. keyLen is the key length in octets.
func NewHMACIntegrity(newHash func() hash.Hash, keyLen, icvLen int) *Integrity {
	return &Integrity{
		newMAC: func(k []byte) hash.Hash { return hmac.New(newHash, k) },
		KeyLen: keyLen,
		ICVLen: icvLen,
	}
}

// Sum computes the truncated MAC over data.
func (i *Integrity) Sum(key, data []byte) []byte {
	m := i.newMAC(key)
	m.Write(data)
	return m.Sum(nil)[:i.ICVLen]
}
