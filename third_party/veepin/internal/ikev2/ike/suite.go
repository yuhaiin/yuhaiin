package ike

import (
	"fmt"

	"github.com/xen0bit/veepin/internal/cryptoutil"
	"github.com/xen0bit/veepin/internal/ikev2/payload"
	"github.com/xen0bit/veepin/internal/ikev2/transform"
)

// Suite is a fully-resolved IKE cipher suite ready for key derivation and SK
// protection.
type Suite struct {
	EncrID    uint16
	EncrKeyLn uint16 // bits; 0 if fixed
	PRFID     uint16
	IntegID   uint16 // 0 for AEAD
	DHID      uint16

	Cipher cryptoutil.SKCipher
	PRF    *cryptoutil.PRF
	Integ  *cryptoutil.Integrity // nil for AEAD
}

// DefaultIKEProposals returns the proposals this endpoint offers for the IKE
// SA, in preference order.
//
// Two proposals, not one, and the split is not cosmetic. RFC 5282 section 8:
// an AEAD cipher carries its own integrity, so a proposal naming one "MUST
// either not include an Integrity Algorithm transform, or include it with the
// value NONE". A single proposal listing AES-GCM, ChaCha20-Poly1305 *and*
// AES-CBC cannot say what it means -- a proposal is one set of transforms from
// which the peer picks one of each type, AES-CBC needs HMAC-SHA2-256-128, and
// AES-GCM needs nothing. veepin sent exactly that: one proposal, four ciphers,
// one INTEG transform reading HMAC_SHA2_256_128 that was true of only one of
// them.
//
// strongSwan accepts it, which is why no cell in the matrix ever noticed.
// libreswan refuses it outright, and is right to:
//
//	no local proposal matches remote proposals 1:IKE:ENCR=AES_GCM_16_256;...;
//	  INTEG=HMAC_SHA2_256_128;DH=CURVE25519;...
//	responding to IKE_SA_INIT message (ID 0) with unencrypted notification
//	  NO_PROPOSAL_CHOSEN
//
// Split, each proposal says something true: proposal 1 is the AEAD suites with
// no integrity transform at all, proposal 2 is AES-CBC with the integrity
// transform it requires. Within each, order signals preference -- AES-GCM
// first (fastest where the CPU has AES-NI), then ChaCha20-Poly1305; SHA2 PRFs;
// elliptic-curve DH groups before MODP-2048, which is ~75x slower per the
// benchmarks. Offering both 128- and 256-bit AES lets a peer negotiate the
// faster 128-bit variant when its policy allows.
func DefaultIKEProposals() []payload.Proposal {
	return []payload.Proposal{
		{
			Num:      1,
			Protocol: payload.ProtoIKE,
			Transforms: []payload.Transform{
				{Type: payload.TransformENCR, ID: payload.ENCR_AES_GCM_16, KeyLen: 256},
				{Type: payload.TransformENCR, ID: payload.ENCR_AES_GCM_16, KeyLen: 128},
				// ChaCha20-Poly1305 (RFC 7634) carries no key-length attribute
				// (the key is always 256-bit), hence KeyLen 0.
				{Type: payload.TransformENCR, ID: payload.ENCR_CHACHA20_P},
				{Type: payload.TransformPRF, ID: payload.PRF_HMAC_SHA2_256},
				{Type: payload.TransformPRF, ID: payload.PRF_HMAC_SHA2_384},
				{Type: payload.TransformPRF, ID: payload.PRF_HMAC_SHA2_512},
				{Type: payload.TransformDH, ID: payload.DH_CURVE25519},
				{Type: payload.TransformDH, ID: payload.DH_ECP_256},
				{Type: payload.TransformDH, ID: payload.DH_ECP_384},
				{Type: payload.TransformDH, ID: payload.DH_MODP_2048},
			},
		},
		{
			Num:      2,
			Protocol: payload.ProtoIKE,
			Transforms: []payload.Transform{
				{Type: payload.TransformENCR, ID: payload.ENCR_AES_CBC, KeyLen: 256},
				{Type: payload.TransformPRF, ID: payload.PRF_HMAC_SHA2_256},
				{Type: payload.TransformPRF, ID: payload.PRF_HMAC_SHA2_384},
				{Type: payload.TransformPRF, ID: payload.PRF_HMAC_SHA2_512},
				{Type: payload.TransformINTEG, ID: payload.AUTH_HMAC_SHA2_256_128},
				{Type: payload.TransformDH, ID: payload.DH_CURVE25519},
				{Type: payload.TransformDH, ID: payload.DH_ECP_256},
				{Type: payload.TransformDH, ID: payload.DH_ECP_384},
				{Type: payload.TransformDH, ID: payload.DH_MODP_2048},
			},
		},
	}
}

// DefaultESPProposals returns the Child SA (ESP) proposals offered, split on
// the same AEAD boundary and for the same reason as [DefaultIKEProposals] --
// RFC 5282 section 8 governs the Child SA's transforms too, and libreswan's
// `esp=aes_gcm256` likewise resolves to AES_GCM_16_256 with integrity NONE.
//
// AES-GCM is offered first: dramatically faster than AES-CBC+HMAC on the data
// path, per the benchmarks. Both proposals carry the same SPI -- it names our
// inbound SA, not the suite, so it does not vary with which one the peer picks.
func DefaultESPProposals(spi []byte) []payload.Proposal {
	return []payload.Proposal{
		{
			Num:      1,
			Protocol: payload.ProtoESP,
			SPI:      spi,
			Transforms: []payload.Transform{
				{Type: payload.TransformENCR, ID: payload.ENCR_AES_GCM_16, KeyLen: 256},
				{Type: payload.TransformENCR, ID: payload.ENCR_AES_GCM_16, KeyLen: 128},
				// ChaCha20-Poly1305 (RFC 7634): AEAD, no key-length attribute.
				{Type: payload.TransformENCR, ID: payload.ENCR_CHACHA20_P},
				{Type: payload.TransformESN, ID: payload.ESN_NONE},
			},
		},
		{
			Num:      2,
			Protocol: payload.ProtoESP,
			SPI:      spi,
			Transforms: []payload.Transform{
				{Type: payload.TransformENCR, ID: payload.ENCR_AES_CBC, KeyLen: 256},
				{Type: payload.TransformINTEG, ID: payload.AUTH_HMAC_SHA2_256_128},
				{Type: payload.TransformESN, ID: payload.ESN_NONE},
			},
		},
	}
}

// isAEAD reports whether an ENCR transform is an AEAD cipher (no separate
// integrity transform is used).
func isAEAD(encrID uint16) bool {
	switch encrID {
	case payload.ENCR_AES_GCM_16, payload.ENCR_CHACHA20_P:
		return true
	default:
		return false
	}
}

// supportedENCR / supportedPRF / etc. gate what we will accept from a peer.
func supportedENCR(id uint16) bool {
	return id == payload.ENCR_AES_GCM_16 || id == payload.ENCR_CHACHA20_P || id == payload.ENCR_AES_CBC
}
func supportedPRF(id uint16) bool {
	switch id {
	case payload.PRF_HMAC_SHA1, payload.PRF_HMAC_SHA2_256, payload.PRF_HMAC_SHA2_384, payload.PRF_HMAC_SHA2_512:
		return true
	}
	return false
}
func supportedInteg(id uint16) bool {
	switch id {
	case payload.AUTH_HMAC_SHA1_96, payload.AUTH_HMAC_SHA2_256_128,
		payload.AUTH_HMAC_SHA2_384_192, payload.AUTH_HMAC_SHA2_512_256:
		return true
	}
	return false
}
func supportedDH(id uint16) bool {
	switch id {
	case payload.DH_CURVE25519, payload.DH_ECP_256, payload.DH_ECP_384,
		payload.DH_ECP_521, payload.DH_MODP_2048:
		return true
	}
	return false
}

// supportedADDKE gates which additional key exchange methods (RFC 9370) we will
// accept in an ADDKE transform. Only ML-KEM-768 is implemented: it is the level
// the IETF hybrid drafts settled on, and crypto/mlkem gives it to us without a
// dependency.
func supportedADDKE(id uint16) bool { return id == payload.MLKEM768 }

// SelectADDKE returns the additional key exchange method the peer proposed in
// its ADDKE1 transform, if we support it. RFC 9370 section 2.1: a proposal that
// omits the transform type is treated as having proposed NONE, so "no ADDKE"
// is the normal, non-error outcome and the caller simply skips the
// IKE_INTERMEDIATE exchange.
//
// Only ADDKE1 is handled. The RFC allows up to seven rounds, but one
// post-quantum KEM alongside the classical group is the whole point of the
// hybrid — the remaining six exist for agility we have no use for yet.
func SelectADDKE(p payload.Proposal) (uint16, bool) {
	tr, ok := chosenTransform(p, payload.TransformADDKE1, supportedADDKE)
	if !ok {
		return 0, false
	}
	return tr.ID, true
}

// chosenTransform picks, for one transform category, the first entry in the
// peer proposal that we support. Returns the transform and whether found.
func chosenTransform(p payload.Proposal, tt payload.TransformType, ok func(uint16) bool) (payload.Transform, bool) {
	for _, tr := range p.Transforms {
		if tr.Type == tt && ok(tr.ID) {
			return tr, true
		}
	}
	return payload.Transform{}, false
}

// SelectIKESuite examines a peer's IKE SA payload and returns the first
// proposal we can fully satisfy, along with the resolved Suite and the
// accepted proposal (to echo back). needDH controls whether a DH group is
// required (true for IKE_SA_INIT).
func SelectIKESuite(sa payload.SAPayload) (Suite, payload.Proposal, error) {
	for _, p := range sa.Proposals {
		if p.Protocol != payload.ProtoIKE {
			continue
		}
		encr, ok := chosenTransform(p, payload.TransformENCR, supportedENCR)
		if !ok {
			continue
		}
		prf, ok := chosenTransform(p, payload.TransformPRF, supportedPRF)
		if !ok {
			continue
		}
		dh, ok := chosenTransform(p, payload.TransformDH, supportedDH)
		if !ok {
			continue
		}
		var integ payload.Transform
		if !isAEAD(encr.ID) {
			integ, ok = chosenTransform(p, payload.TransformINTEG, supportedInteg)
			if !ok {
				continue
			}
		}
		suite, err := buildSuite(encr, prf, integ, dh)
		if err != nil {
			continue
		}
		accepted := payload.Proposal{
			Num:      p.Num,
			Protocol: payload.ProtoIKE,
			Transforms: []payload.Transform{
				{Type: payload.TransformENCR, ID: encr.ID, KeyLen: encr.KeyLen},
				{Type: payload.TransformPRF, ID: prf.ID},
			},
		}
		if !isAEAD(encr.ID) {
			accepted.Transforms = append(accepted.Transforms,
				payload.Transform{Type: payload.TransformINTEG, ID: integ.ID})
		}
		accepted.Transforms = append(accepted.Transforms,
			payload.Transform{Type: payload.TransformDH, ID: dh.ID})
		return suite, accepted, nil
	}
	return Suite{}, payload.Proposal{}, fmt.Errorf("ike: no acceptable IKE proposal")
}

func buildSuite(encr, prf, integ, dh payload.Transform) (Suite, error) {
	c, err := transform.Cipher(encr.ID, int(encr.KeyLen))
	if err != nil {
		return Suite{}, err
	}
	pf, err := transform.PRF(prf.ID)
	if err != nil {
		return Suite{}, err
	}
	s := Suite{
		EncrID: encr.ID, EncrKeyLn: encr.KeyLen, PRFID: prf.ID, DHID: dh.ID,
		Cipher: c, PRF: pf,
	}
	if !isAEAD(encr.ID) {
		ig, err := transform.Integrity(integ.ID)
		if err != nil {
			return Suite{}, err
		}
		s.IntegID = integ.ID
		s.Integ = ig
	}
	return s, nil
}

// encKeyLen returns the per-direction encryption key length in bytes.
func (s *Suite) encKeyLen() int { return s.Cipher.KeyLen() }

// integKeyLen returns the per-direction integrity key length in bytes (0 for AEAD).
func (s *Suite) integKeyLen() int {
	if s.Integ == nil {
		return 0
	}
	return s.Integ.KeyLen
}

// ESPSuite is the resolved Child SA cipher suite (encryption + optional integ).
type ESPSuite struct {
	EncrID    uint16
	EncrKeyLn uint16
	IntegID   uint16
	Cipher    cryptoutil.SKCipher
	Integ     *cryptoutil.Integrity
}

// SelectESPSuite picks the first acceptable ESP proposal from the peer.
func SelectESPSuite(sa payload.SAPayload) (ESPSuite, payload.Proposal, error) {
	for _, p := range sa.Proposals {
		if p.Protocol != payload.ProtoESP {
			continue
		}
		encr, ok := chosenTransform(p, payload.TransformENCR, supportedENCR)
		if !ok {
			continue
		}
		var integ payload.Transform
		if !isAEAD(encr.ID) {
			integ, ok = chosenTransform(p, payload.TransformINTEG, supportedInteg)
			if !ok {
				continue
			}
		}
		c, err := transform.Cipher(encr.ID, int(encr.KeyLen))
		if err != nil {
			continue
		}
		es := ESPSuite{EncrID: encr.ID, EncrKeyLn: encr.KeyLen, Cipher: c}
		accepted := payload.Proposal{
			Num:      p.Num,
			Protocol: payload.ProtoESP,
			SPI:      p.SPI,
			Transforms: []payload.Transform{
				{Type: payload.TransformENCR, ID: encr.ID, KeyLen: encr.KeyLen},
			},
		}
		if !isAEAD(encr.ID) {
			ig, err := transform.Integrity(integ.ID)
			if err != nil {
				continue
			}
			es.IntegID = integ.ID
			es.Integ = ig
			accepted.Transforms = append(accepted.Transforms,
				payload.Transform{Type: payload.TransformINTEG, ID: integ.ID})
		}
		accepted.Transforms = append(accepted.Transforms,
			payload.Transform{Type: payload.TransformESN, ID: payload.ESN_NONE})
		return es, accepted, nil
	}
	return ESPSuite{}, payload.Proposal{}, fmt.Errorf("ike: no acceptable ESP proposal")
}
