package ike

import (
	"encoding/binary"
	"fmt"

	"github.com/xen0bit/veepin/internal/cryptoutil"
	"github.com/xen0bit/veepin/internal/ikev2/payload"
)

// keyDir selects which directional keys to use.
type keyDir int

const (
	dirInitiatorToResponder keyDir = iota
	dirResponderToInitiator
)

// encryptKeys returns (encKey, integKey) for the given direction.
func encryptKeys(keys SAKeys, dir keyDir) (enc, integ []byte) {
	switch dir {
	case dirInitiatorToResponder:
		return keys.SKei, keys.SKai
	default:
		return keys.SKer, keys.SKar
	}
}

// buildEncryptedMessage constructs a full IKEv2 message whose sole top-level
// payload is an SK payload wrapping innerPayloads. firstInner is the payload
// type of the first inner payload (goes into the SK generic header's
// NextPayload field).
//
// The AAD for the SK cipher is: IKE header (with final length) followed by the
// SK payload's own generic header. Since the SK payload is the only top-level
// payload, that is exactly the message bytes up to the start of the SK body.
func buildEncryptedMessage(hdr payload.Header, suite Suite, keys SAKeys,
	dir keyDir, firstInner payload.PayloadType, innerPayloads []byte) ([]byte, error) {

	encKey, integKey := encryptKeys(keys, dir)

	// Compute SK body length: iv + padded-ciphertext + icv. We seal first to
	// learn the exact length, then assemble headers around it.
	//
	// But sealing needs the AAD, which depends on the final message length,
	// which depends on the sealed length. Resolve by computing lengths up front.
	ivLen := suite.Cipher.IVLen()
	icvLen := suite.Cipher.ICVLen()
	if suite.Integ != nil {
		icvLen = suite.Integ.ICVLen
	}
	block := suite.Cipher.BlockLen()

	// Ciphertext length after RFC 7296 padding: plaintext + padlen-octet,
	// rounded up to the block size.
	ptLen := len(innerPayloads)
	var ctLen int
	if block <= 1 {
		// Stream/AEAD ciphers do no block padding, but RFC 7296 still mandates
		// the Pad Length octet, so the plaintext carries a single 0 pad-length.
		ctLen = ptLen + 1
	} else {
		padLen := block - (ptLen+1)%block
		if padLen == block {
			padLen = 0
		}
		ctLen = ptLen + padLen + 1
	}
	skBodyLen := ivLen + ctLen + icvLen
	skPayloadLen := 4 + skBodyLen // generic header + body
	total := payload.HeaderLen + skPayloadLen

	// Header with SK as the first (only) top-level payload.
	hdr.NextPayload = payload.TypeSK
	hdr.Version = 0x20
	hdr.Length = uint32(total)

	// AAD = header || SK generic header.
	aad := make([]byte, 0, payload.HeaderLen+4)
	aad = hdr.Marshal(aad)
	skGeneric := [4]byte{
		byte(firstInner), 0x00,
		byte(skPayloadLen >> 8), byte(skPayloadLen),
	}
	aad = append(aad, skGeneric[:]...)

	// Seal the plaintext (inner payloads). For AEAD, we hand the raw inner
	// payloads and let RFC 7296 padding be represented by appending the pad and
	// padlen ourselves so the wire format is identical to the CBC path.
	sealed, err := sealSK(suite, encKey, integKey, aad, innerPayloads)
	if err != nil {
		return nil, err
	}
	if len(sealed) != skBodyLen {
		return nil, fmt.Errorf("ike: SK body length mismatch: got %d want %d", len(sealed), skBodyLen)
	}

	out := make([]byte, 0, total)
	out = append(out, aad...) // header + SK generic header
	out = append(out, sealed...)
	return out, nil
}

// sealSK produces iv||ciphertext||icv for the given inner payload bytes,
// applying RFC 7296 padding uniformly across AEAD and CBC.
func sealSK(suite Suite, encKey, integKey, aad, inner []byte) ([]byte, error) {
	if suite.Integ == nil {
		// AEAD path: the padding + pad-length octet are inside the AEAD
		// plaintext. Append minimal padding (0 pad + padlen octet).
		padded := append(append([]byte(nil), inner...), 0x00) // padlen = 0
		return suite.Cipher.Seal(encKey, nil, aad, padded)
	}
	// CBC encrypt-then-MAC path. Apply RFC 7296 padding (pad octets counting
	// 1..padLen, then a pad-length octet) so the result is block-aligned.
	cbc, ok := suite.Cipher.(interface {
		SealETM(encKey, integKey, aad, plaintext []byte, integ *cryptoutil.Integrity) ([]byte, error)
	})
	if !ok {
		return nil, fmt.Errorf("ike: non-AEAD cipher lacks SealETM")
	}
	padded := padRFC7296(inner, suite.Cipher.BlockLen())
	return cbc.SealETM(encKey, integKey, aad, padded, suite.Integ)
}

// padRFC7296 pads plaintext so that len+1 is a multiple of block: it appends
// padLen octets valued 1..padLen followed by the pad-length octet (RFC 7296
// section 3.14). For block <= 1 it appends only a zero pad-length octet.
func padRFC7296(pt []byte, block int) []byte {
	if block <= 1 {
		return append(append([]byte(nil), pt...), 0x00)
	}
	padLen := block - (len(pt)+1)%block
	if padLen == block {
		padLen = 0
	}
	out := append([]byte(nil), pt...)
	for i := 0; i < padLen; i++ {
		out = append(out, byte(i+1))
	}
	out = append(out, byte(padLen))
	return out
}

// decryptSK verifies and decrypts the SK payload of a received message and
// returns the inner payload chain plus the SK generic header's NextPayload
// (type of the first inner payload).
func decryptSK(raw []byte, hdr payload.Header, skPayload payload.RawPayload,
	suite Suite, keys SAKeys, dir keyDir) (firstInner payload.PayloadType, inner []byte, err error) {

	encKey, integKey := encryptKeys(keys, dir)

	// The SK body is skPayload.Body. AAD is everything before the SK body:
	// header + SK generic header = raw[:len(raw)-len(skPayload.Body)].
	bodyStart := len(raw) - len(skPayload.Body)
	if bodyStart < payload.HeaderLen+4 {
		return 0, nil, fmt.Errorf("ike: malformed SK payload framing")
	}
	aad := raw[:bodyStart]

	// firstInner comes from the SK generic header NextPayload byte.
	firstInner = payload.PayloadType(raw[bodyStart-4])

	padded, err := openSK(suite, encKey, integKey, aad, skPayload.Body)
	if err != nil {
		return 0, nil, err
	}
	inner, err = stripRFC7296Pad(padded)
	if err != nil {
		return 0, nil, err
	}
	return firstInner, inner, nil
}

// openSK verifies and decrypts an iv||ciphertext||icv unit under the SK/SKF
// cipher with the given associated data, returning the still-padded plaintext.
// It is the inbound counterpart shared by the whole SK and SKF (RFC 7383) paths.
func openSK(suite Suite, encKey, integKey, aad, ivCtIcv []byte) ([]byte, error) {
	if suite.Integ == nil {
		return suite.Cipher.Open(encKey, nil, aad, ivCtIcv)
	}
	cbc, ok := suite.Cipher.(interface {
		OpenETM(encKey, integKey, aad, ivCtIcv []byte, integ *cryptoutil.Integrity) ([]byte, error)
	})
	if !ok {
		return nil, fmt.Errorf("ike: non-AEAD cipher lacks OpenETM")
	}
	return cbc.OpenETM(encKey, integKey, aad, ivCtIcv, suite.Integ)
}

// stripRFC7296Pad removes RFC 7296 section 3.14 padding from a decrypted SK/SKF
// plaintext: the final octet is the pad length and the preceding padLen octets
// are padding.
func stripRFC7296Pad(padded []byte) ([]byte, error) {
	if len(padded) == 0 {
		return nil, nil
	}
	padLen := int(padded[len(padded)-1])
	if padLen+1 > len(padded) {
		return nil, fmt.Errorf("ike: bad SK pad length %d", padLen)
	}
	return padded[:len(padded)-padLen-1], nil
}

// parseInnerPayloads decodes the decrypted inner payload chain.
func parseInnerPayloads(first payload.PayloadType, inner []byte) ([]payload.RawPayload, error) {
	// Reuse the top-level chain parser by exposing it. Since it's unexported in
	// the payload package, we reimplement the walk here.
	var out []payload.RawPayload
	next := first
	off := 0
	for next != payload.NoNextPayload {
		if off+4 > len(inner) {
			return nil, payload.ErrTruncated
		}
		thisType := next
		nextType := payload.PayloadType(inner[off])
		critical := inner[off+1]&0x80 != 0
		length := int(binary.BigEndian.Uint16(inner[off+2 : off+4]))
		if length < 4 || off+length > len(inner) {
			return nil, fmt.Errorf("ike: bad inner payload length %d for %s", length, thisType)
		}
		out = append(out, payload.RawPayload{
			Type: thisType, Critical: critical, Body: inner[off+4 : off+length],
		})
		off += length
		next = nextType
	}
	return out, nil
}
