package sstp

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/xen0bit/veepin/internal/mschap"
	"github.com/xen0bit/veepin/internal/sstp/wire"
)

var sstpLabel = []byte("SSTP inner method derived CMK")

// prfPlus derives n bytes using the SSTP variant of PRF+ (MS-SSTP section
// 3.2.5.2.2). Unlike IKEv2 PRF+, every iteration includes the total
// requested length as a 16-bit little-endian field before the counter:
//
//	T_i = HMAC-SHA256(K, T_{i-1} | S | LEN_{LE} | i)
func prfPlus(key, seed []byte, n int) []byte {
	h := hmac.New(sha256.New, key)

	lenLE := make([]byte, 2)
	binary.LittleEndian.PutUint16(lenLE, uint16(n))

	out := make([]byte, 0, n)
	var prev []byte
	var counter [1]byte
	for len(out) < n {
		counter[0]++
		h.Reset()
		h.Write(prev)
		h.Write(seed)
		h.Write(lenLE)
		h.Write(counter[:])
		prev = h.Sum(nil)
		out = append(out, prev...)
	}
	return out[:n]
}

// DeriveCMK computes the compound MAC key from the HLAK:
//
//	CMK = PRF+(HLAK, "SSTP inner method derived CMK", 32)
func DeriveCMK(hlak [mschap.HLAKLen]byte) []byte {
	return prfPlus(hlak[:], sstpLabel, 32)
}

// CBValueLen is the total length of a crypto-binding attribute value.
const CBValueLen = 1 + 1 + 2 + wire.NonceLen + wire.CertHashLen + wire.CompoundMACLen

// BuildCBValue constructs the crypto-binding attribute value for a
// CallConnected message. The layout (MS-SSTP 2.2.2) is Reserved(3) |
// HashProtocol(1) | Nonce(32) | CertHash(32) | CompoundMAC(32); only SHA-256 is
// implemented, so the hash protocol byte is always CertHashSHA256.
func BuildCBValue(nonce, certHash, compoundMAC []byte) []byte {
	v := make([]byte, CBValueLen)
	v[3] = wire.CertHashSHA256
	copy(v[4:36], nonce)
	copy(v[36:68], certHash)
	copy(v[68:100], compoundMAC)
	return v
}

// VerifyCryptoBinding verifies the crypto-binding attribute in an
// SSTP_MSG_CALL_CONNECTED control message body: the certificate hash matches the
// server's own certificate, and the compound MAC over the whole packet (the
// 4-octet packet header prepended to body, with the MAC field zeroed) reproduces
// under the CMK derived from the client's HLAK.
func VerifyCryptoBinding(body []byte, hlak [mschap.HLAKLen]byte, serverCertDER []byte) error {
	cb, mac, err := extractAndZeroMAC(body)
	if err != nil {
		return fmt.Errorf("sstp: crypto binding: %w", err)
	}

	expectedHash := sha256.Sum256(serverCertDER)
	if !bytes.Equal(cb[36:68], expectedHash[:]) {
		return fmt.Errorf("sstp: cert hash mismatch")
	}

	cmk := DeriveCMK(hlak)
	h := hmac.New(sha256.New, cmk)
	h.Write(controlPacketHeader(len(body)))
	h.Write(body)
	expectedMAC := h.Sum(nil)

	if !hmac.Equal(mac, expectedMAC) {
		return fmt.Errorf("sstp: compound MAC mismatch")
	}
	return nil
}

// controlPacketHeader reconstructs the 4-octet SSTP header for a control packet
// whose body is bodyLen bytes: version, the control flag, and the total length.
// The compound MAC covers the packet including this header.
func controlPacketHeader(bodyLen int) []byte {
	total := wire.HeaderLen + bodyLen
	return []byte{wire.Version, 0x01, byte(total >> 8), byte(total)}
}

// extractAndZeroMAC locates ATTRIB_CRYPTO_BINDING in the body, returns its value
// and the MAC bytes, and zeros the MAC in body.
func extractAndZeroMAC(body []byte) (value []byte, mac []byte, err error) {
	if len(body) < 4 {
		return nil, nil, wire.ErrMalformed
	}
	num := int(binary.BigEndian.Uint16(body[2:4]))
	b := body[4:]
	for range num {
		if len(b) < 4 {
			return nil, nil, wire.ErrMalformed
		}
		length := int(binary.BigEndian.Uint16(b[2:4]) & 0x0fff)
		if length < 4 || length > len(b) {
			return nil, nil, wire.ErrMalformed
		}
		if b[1] == wire.AttrCryptoBinding {
			val := b[4:length]
			if len(val) < CBValueLen {
				return nil, nil, fmt.Errorf("%w: short crypto binding value", wire.ErrMalformed)
			}
			macStart := len(val) - wire.CompoundMACLen
			mac = append([]byte(nil), val[macStart:]...)
			for i := range val[macStart:] {
				val[macStart+i] = 0
			}
			return val, mac, nil
		}
		b = b[length:]
	}
	return nil, nil, fmt.Errorf("sstp: no crypto binding attribute found")
}
