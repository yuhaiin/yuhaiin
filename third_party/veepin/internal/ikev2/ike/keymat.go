package ike

import (
	"encoding/binary"

	"github.com/xen0bit/veepin/internal/cryptoutil"
)

// SAKeys holds the derived IKE SA keying material (RFC 7296 section 2.14).
type SAKeys struct {
	SKd  []byte // used to derive Child SA keys
	SKai []byte // integrity, initiator->responder
	SKar []byte // integrity, responder->initiator
	SKei []byte // encryption, initiator->responder
	SKer []byte // encryption, responder->initiator
	SKpi []byte // AUTH generation, initiator
	SKpr []byte // AUTH generation, responder
}

// DeriveIKEKeys computes SKEYSEED and the seven SK_* values.
//
//	SKEYSEED = prf(Ni | Nr, g^ir)
//	{SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr}
//	    = prf+(SKEYSEED, Ni | Nr | SPIi | SPIr)
//
// encKeyLen and integKeyLen are per-direction key lengths in bytes. For AEAD
// ciphers integKeyLen is 0.
func DeriveIKEKeys(prf *cryptoutil.PRF, sharedSecret, ni, nr []byte, spiI, spiR uint64,
	encKeyLen, integKeyLen int) (skeyseed []byte, keys SAKeys) {

	nonces := append(append([]byte(nil), ni...), nr...)
	skeyseed = prf.Apply(nonces, sharedSecret)
	return skeyseed, expandIKEKeys(prf, skeyseed, ni, nr, spiI, spiR, encKeyLen, integKeyLen)
}

// DeriveRekeyedIKEKeys computes the seven SK_* values for an IKE SA created by
// rekeying an existing one (RFC 7296 section 2.18). It differs from the initial
// derivation only in how SKEYSEED is seeded — from the old SA's SK_d and the
// fresh DH secret rather than from the nonces alone:
//
//	SKEYSEED = prf(SK_d (old), g^ir (new) | Ni | Nr)
//	{SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr}
//	    = prf+(SKEYSEED, Ni | Nr | SPIi | SPIr)
//
// prf and the key lengths are the new SA's negotiated PRF and per-direction key
// lengths; oldSKd is SK_d from the SA being replaced. Ni/Nr and SPIi/SPIr are
// the new exchange's nonces and IKE SPIs.
func DeriveRekeyedIKEKeys(prf *cryptoutil.PRF, oldSKd, dhSecret, ni, nr []byte,
	spiI, spiR uint64, encKeyLen, integKeyLen int) SAKeys {

	seed := make([]byte, 0, len(dhSecret)+len(ni)+len(nr))
	seed = append(seed, dhSecret...)
	seed = append(seed, ni...)
	seed = append(seed, nr...)
	skeyseed := prf.Apply(oldSKd, seed)
	return expandIKEKeys(prf, skeyseed, ni, nr, spiI, spiR, encKeyLen, integKeyLen)
}

// expandIKEKeys runs the prf+ expansion shared by the initial and rekeyed IKE
// key derivations: {SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr}
// = prf+(SKEYSEED, Ni | Nr | SPIi | SPIr).
func expandIKEKeys(prf *cryptoutil.PRF, skeyseed, ni, nr []byte, spiI, spiR uint64,
	encKeyLen, integKeyLen int) SAKeys {

	seed := make([]byte, 0, len(ni)+len(nr)+16)
	seed = append(seed, ni...)
	seed = append(seed, nr...)
	var spi [8]byte
	binary.BigEndian.PutUint64(spi[:], spiI)
	seed = append(seed, spi[:]...)
	binary.BigEndian.PutUint64(spi[:], spiR)
	seed = append(seed, spi[:]...)

	total := prf.Size + 2*integKeyLen + 2*encKeyLen + 2*prf.Size
	km := prf.Plus(skeyseed, seed, total)

	off := 0
	take := func(n int) []byte {
		b := km[off : off+n]
		off += n
		return b
	}
	var keys SAKeys
	keys.SKd = take(prf.Size)
	keys.SKai = take(integKeyLen)
	keys.SKar = take(integKeyLen)
	keys.SKei = take(encKeyLen)
	keys.SKer = take(encKeyLen)
	keys.SKpi = take(prf.Size)
	keys.SKpr = take(prf.Size)
	return keys
}

// DeriveIntermediateSKEYSEED computes the new SKEYSEED after an IKE_INTERMEDIATE
// exchange with an additional key exchange (RFC 9370 section 2.2). The shared
// secret from the additional key exchange is mixed into SKEYSEED by chaining it
// through the existing SA's SK_d:
//
//	SKEYSEED = prf(SK_d(prev), sharedSecret | SK_i | ...)
//
// The SK_i is the initiator's nonce from the intermediate exchange; for the
// initiator this is Ni, for the responder Nr. The order matters and is specified:
// the new shared secret comes first, then the intermediate exchange's nonces.
func DeriveIntermediateSKEYSEED(prf *cryptoutil.PRF, prevSKd, newSharedSecret, ni, nr []byte) []byte {
	seed := make([]byte, 0, len(newSharedSecret)+len(ni)+len(nr))
	seed = append(seed, newSharedSecret...)
	seed = append(seed, ni...)
	seed = append(seed, nr...)
	return prf.Apply(prevSKd, seed)
}

// DeriveChildKeys computes the Child SA keying material (RFC 7296 2.17):
//
//	KEYMAT = prf+(SK_d, [g^ir (new)] | Ni | Nr)
//
// When there is no new DH exchange for the child (the common case), the DH
// output is empty. The caller slices the result per the negotiated ESP
// suite: encr_i | integ_i | encr_r | integ_r.
func DeriveChildKeys(prf *cryptoutil.PRF, skd, dhSecret, ni, nr []byte, total int) []byte {
	seed := make([]byte, 0, len(dhSecret)+len(ni)+len(nr))
	seed = append(seed, dhSecret...)
	seed = append(seed, ni...)
	seed = append(seed, nr...)
	return prf.Plus(skd, seed, total)
}

// AuthOctets computes the data signed/MAC'd by an endpoint's AUTH payload
// (RFC 7296 section 2.15, extended by RFC 9242 section 3.3):
//
//	InitiatorSignedOctets = RealMessage1 | NonceRData | prf(SK_pi, IDi') | IntAuth
//	ResponderSignedOctets = RealMessage2 | NonceIData | prf(SK_pr, IDr') | IntAuth
//
// realMessage is the first message this endpoint sent (the full IKE_SA_INIT
// request for the initiator, or response for the responder). peerNonce is the
// other side's nonce. idPayload is the ID payload body (type + reserved + data),
// i.e. everything after the generic payload header, hashed with the endpoint's
// own SK_p.
//
// intAuth covers any IKE_INTERMEDIATE exchanges (see [finalIntAuth]) and is nil
// when there were none, which degrades this to plain RFC 7296. It goes last,
// after the ID hash — not between the message and the nonce, which would be a
// change both endpoints could agree on while no other implementation did.
func AuthOctets(prf *cryptoutil.PRF, realMessage, peerNonce, skp, idPayload, intAuth []byte) []byte {
	idPrime := prf.Apply(skp, idPayload)
	out := make([]byte, 0, len(realMessage)+len(peerNonce)+len(idPrime)+len(intAuth))
	out = append(out, realMessage...)
	out = append(out, peerNonce...)
	out = append(out, idPrime...)
	out = append(out, intAuth...)
	return out
}

// PSKAuth computes the AUTH payload value for shared-key authentication
// (RFC 7296 section 2.15):
//
//	AUTH = prf(prf(Shared Secret, "Key Pad for IKEv2"), <signed octets>)
func PSKAuth(prf *cryptoutil.PRF, psk, signedOctets []byte) []byte {
	const keyPad = "Key Pad for IKEv2"
	inner := prf.Apply(psk, []byte(keyPad))
	return prf.Apply(inner, signedOctets)
}
