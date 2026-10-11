package ikev1

import (
	"hash"

	"github.com/xen0bit/veepin/internal/cryptoutil"
)

// phase1 holds the keying material derived from a completed Main Mode DH: the
// SKEYID family (RFC 2409 section 5), the phase-1 encryption key, and the running
// CBC IV. Both ends derive it identically.
type phase1 struct {
	prf     *cryptoutil.PRF
	newHash func() hash.Hash

	skeyid  []byte
	skeyidD []byte
	skeyidA []byte
	skeyidE []byte

	encKey []byte
	iv     []byte // running CBC IV for message-ID 0 (the phase-1 exchange)
}

// derivePhase1 computes the SKEYID family for pre-shared-key authentication.
//
//	SKEYID   = prf(psk, Ni_b | Nr_b)
//	SKEYID_d = prf(SKEYID, g^xy | CKY-I | CKY-R | 0)
//	SKEYID_a = prf(SKEYID, SKEYID_d | g^xy | CKY-I | CKY-R | 1)
//	SKEYID_e = prf(SKEYID, SKEYID_a | g^xy | CKY-I | CKY-R | 2)
func derivePhase1(prf *cryptoutil.PRF, newHash func() hash.Hash, psk, ni, nr, dhShared []byte, ckyI, ckyR [8]byte, encKeyLen int) *phase1 {
	p := &phase1{prf: prf, newHash: newHash}
	p.skeyid = prf.Apply(psk, concat(ni, nr))

	base := concat(dhShared, ckyI[:], ckyR[:])
	p.skeyidD = prf.Apply(p.skeyid, append(append([]byte(nil), base...), 0))
	p.skeyidA = prf.Apply(p.skeyid, concat(p.skeyidD, base, []byte{1}))
	p.skeyidE = prf.Apply(p.skeyid, concat(p.skeyidA, base, []byte{2}))
	p.encKey = expandKey(prf, p.skeyidE, encKeyLen)
	return p
}

// expandKey derives an encryption key of keyLen octets from SKEYID_e (RFC 2409
// Appendix B): use the high-order bits when SKEYID_e is long enough, otherwise
// iterate K1 = prf(SKEYID_e, 0x00), Kn = prf(SKEYID_e, Kn-1).
func expandKey(prf *cryptoutil.PRF, skeyidE []byte, keyLen int) []byte {
	if len(skeyidE) >= keyLen {
		return append([]byte(nil), skeyidE[:keyLen]...)
	}
	block := prf.Apply(skeyidE, []byte{0x00})
	out := append([]byte(nil), block...)
	for len(out) < keyLen {
		block = prf.Apply(skeyidE, block)
		out = append(out, block...)
	}
	return out[:keyLen]
}

// setInitialIV seeds the phase-1 CBC IV from the DH public values (RFC 2409
// Appendix B): IV0 = hash(g^xi | g^xr) truncated to the cipher block size.
func (p *phase1) setInitialIV(gxi, gxr []byte) {
	h := p.newHash()
	h.Write(gxi)
	h.Write(gxr)
	p.iv = h.Sum(nil)[:aesBlockSize]
}

// quickModeIV derives the initial IV for a Quick Mode exchange (message ID m):
// hash(last phase-1 IV | m) truncated to the block size.
func (p *phase1) quickModeIV(messageID uint32) []byte {
	h := p.newHash()
	h.Write(p.iv)
	h.Write(be32(messageID))
	return h.Sum(nil)[:aesBlockSize]
}

// hashI is the initiator's authenticating hash (RFC 2409 section 5):
//
//	HASH_I = prf(SKEYID, g^xi | g^xr | CKY-I | CKY-R | SAi_b | IDii_b)
func (p *phase1) hashI(gxi, gxr []byte, ckyI, ckyR [8]byte, saBody, idBody []byte) []byte {
	return p.prf.Apply(p.skeyid, concat(gxi, gxr, ckyI[:], ckyR[:], saBody, idBody))
}

// hashR is the responder's authenticating hash:
//
//	HASH_R = prf(SKEYID, g^xr | g^xi | CKY-R | CKY-I | SAi_b | IDir_b)
func (p *phase1) hashR(gxi, gxr []byte, ckyI, ckyR [8]byte, saBody, idBody []byte) []byte {
	return p.prf.Apply(p.skeyid, concat(gxr, gxi, ckyR[:], ckyI[:], saBody, idBody))
}

// keymat expands the ESP keying material for one SA direction (RFC 2409 section
// 5.5, no PFS):
//
//	KEYMAT = prf(SKEYID_d, protocol | SPI | Ni_b | Nr_b) [| prf(SKEYID_d, prev | ...)]
//
// It returns n octets, from which the caller slices the encryption then the
// integrity key.
func (p *phase1) keymat(proto uint8, spi, ni, nr []byte, n int) []byte {
	seed := concat([]byte{proto}, spi, ni, nr)
	block := p.prf.Apply(p.skeyidD, seed)
	out := append([]byte(nil), block...)
	for len(out) < n {
		block = p.prf.Apply(p.skeyidD, concat(block, seed))
		out = append(out, block...)
	}
	return out[:n]
}

func concat(parts ...[]byte) []byte {
	var n int
	for _, part := range parts {
		n += len(part)
	}
	out := make([]byte, 0, n)
	for _, part := range parts {
		out = append(out, part...)
	}
	return out
}
