package pulse

// The two codecs authentication is built out of: EAP packets, and the
// Diameter-style AVPs Juniper carries inside them.
//
// EAP here is ordinary RFC 3748 framing (code, identifier, length, type) with
// the Expanded type (254) used to reach Juniper's own vendor space. An expanded
// EAP header is 12 octets rather than 5: the type octet, three octets of vendor
// ID, then a four-octet vendor type.
//
// The AVPs are RFC 6733 shaped but not quite RFC 6733: the length field counts
// the whole AVP including its header, values are padded to a four-octet
// boundary, and Juniper always sets the vendor bit and its second enterprise
// number. Nothing here reads a flag it does not need — the point is to render
// what a real client accepts and to read what one sends.

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// EAP codes (RFC 3748 section 4).
const (
	EAPRequest  = 1
	EAPResponse = 2
	EAPSuccess  = 3
	EAPFailure  = 4
)

// EAP types used here.
const (
	EAPTypeIdentity = 1
	EAPTypeGTC      = 6
	EAPTypeTTLS     = 0x15
	EAPTypeExpanded = 0xfe
)

// eapHeaderLen is code(1) | identifier(1) | length(2) | type(1).
const eapHeaderLen = 5

// eapExpandedHeaderLen is the same with the three-octet vendor ID and the
// four-octet vendor type in place of the single type octet.
const eapExpandedHeaderLen = 12

// Juniper's expanded EAP subtypes. Subtype 1 carries the AVP conversation;
// subtype 2 is the password request and response.
const (
	JuniperSubtypeAVP      = 1
	JuniperSubtypePassword = 2
)

// Password-request codes inside Juniper subtype 2.
const (
	PassRequest = 0x01
	PassRetry   = 0x81
	PassChange  = 0x43
	PassFail    = 0xc5
)

// AVP codes. The EAP-Message code is the standard Diameter one; the rest are
// Juniper's, in its second enterprise space.
const (
	AVPEAPMessage = 79

	AVPRealmList   = 0x0d4e // the realms a user may choose between
	AVPCookie      = 0x0d53 // the session cookie ("DSID")
	AVPSigninName  = 0x0d55 // the sign-in page name
	AVPClientOS    = 0x0d5e // "Windows", "Linux", ...
	AVPUsername    = 0x0d6d // the username, in the password response
	AVPUserAgent   = 0x0d70 // "Pulse-Secure/<version> (<platform>)"
	AVPPromptFlags = 0x0d73 // 1 = prompt for both, 3 = password only
)

// avpHeaderLen is code(4) | flags(2) | length(2) | vendor(4).
const avpHeaderLen = 12

// AVP is one decoded attribute-value pair.
type AVP struct {
	Code   uint32
	Vendor uint32
	Value  []byte
}

// EncodeAVP renders one Juniper AVP: the code, the vendor flag, the total
// length, the vendor, then the value padded out to a four-octet boundary.
//
// The length field counts the header but *not* the padding, which is the one
// place this differs from a reading of RFC 6733 that would make the padding
// part of the AVP. openconnect writes it this way and reads it this way, so a
// server that padded the length would produce AVPs it rejects.
func EncodeAVP(code uint32, value []byte) []byte {
	pad := (4 - len(value)%4) % 4
	out := make([]byte, avpHeaderLen+len(value)+pad)
	binary.BigEndian.PutUint32(out[0:4], code)
	binary.BigEndian.PutUint16(out[4:6], 0x8000) // vendor-specific
	binary.BigEndian.PutUint16(out[6:8], uint16(avpHeaderLen+len(value)))
	binary.BigEndian.PutUint32(out[8:12], VendorJuniper2)
	copy(out[avpHeaderLen:], value)
	return out
}

// EncodeAVPString is EncodeAVP for a text value.
func EncodeAVPString(code uint32, s string) []byte { return EncodeAVP(code, []byte(s)) }

// EncodeAVPUint32 is EncodeAVP for a four-octet integer value.
func EncodeAVPUint32(code, v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return EncodeAVP(code, b[:])
}

// encodeAVPRaw renders an AVP with no vendor: the shape the EAP-Message AVP
// takes, whose code is standard rather than Juniper's.
func encodeAVPRaw(code uint32, value []byte) []byte {
	pad := (4 - len(value)%4) % 4
	out := make([]byte, 8+len(value)+pad)
	binary.BigEndian.PutUint32(out[0:4], code)
	binary.BigEndian.PutUint16(out[4:6], 0x4000) // mandatory, not vendor-specific
	binary.BigEndian.PutUint16(out[6:8], uint16(8+len(value)))
	copy(out[8:], value)
	return out
}

var errShortAVP = errors.New("pulse: truncated AVP")

// ParseAVPs walks an AVP chain. Values alias the input.
func ParseAVPs(buf []byte) ([]AVP, error) {
	var out []AVP
	for len(buf) > 0 {
		if len(buf) < 8 {
			return nil, errShortAVP
		}
		code := binary.BigEndian.Uint32(buf[0:4])
		flags := binary.BigEndian.Uint16(buf[4:6])
		length := int(binary.BigEndian.Uint16(buf[6:8]))

		hdr := 8
		var vendor uint32
		if flags&0x8000 != 0 {
			if len(buf) < avpHeaderLen {
				return nil, errShortAVP
			}
			vendor = binary.BigEndian.Uint32(buf[8:12])
			hdr = avpHeaderLen
		}
		if length < hdr || length > len(buf) {
			return nil, fmt.Errorf("pulse: AVP length %d out of range", length)
		}
		out = append(out, AVP{Code: code, Vendor: vendor, Value: buf[hdr:length]})

		// Advance past the value's four-octet padding, which the length field
		// does not count. A chain whose final AVP is unpadded ends here rather
		// than running off the end.
		buf = buf[min(length+(4-length%4)%4, len(buf)):]
	}
	return out, nil
}

// FindAVP returns the first AVP with the given code.
func FindAVP(avps []AVP, code uint32) (AVP, bool) {
	for _, a := range avps {
		if a.Code == code {
			return a, true
		}
	}
	return AVP{}, false
}

// EAPPacket is one decoded EAP packet. For an expanded packet, Vendor and
// Subtype are filled in and Data is what follows the 12-octet header;
// otherwise Type is the plain EAP type and Data follows the 5-octet one.
type EAPPacket struct {
	Code     uint8
	Ident    uint8
	Type     uint8
	Vendor   uint32
	Subtype  uint32
	Data     []byte
	Expanded bool
}

// EncodeEAP renders a plain (non-expanded) EAP packet.
func EncodeEAP(code, ident, typ uint8, data []byte) []byte {
	out := make([]byte, eapHeaderLen+len(data))
	out[0] = code
	out[1] = ident
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	out[4] = typ
	copy(out[eapHeaderLen:], data)
	return out
}

// EncodeEAPExpanded renders an EAP packet of Juniper's expanded type.
func EncodeEAPExpanded(code, ident uint8, subtype uint32, data []byte) []byte {
	out := make([]byte, eapExpandedHeaderLen+len(data))
	out[0] = code
	out[1] = ident
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	// The expanded type octet and the 24-bit vendor ID share one word.
	binary.BigEndian.PutUint32(out[4:8], EAPTypeExpanded<<24|VendorJuniper)
	binary.BigEndian.PutUint32(out[8:12], subtype)
	copy(out[eapExpandedHeaderLen:], data)
	return out
}

// EncodeEAPResult renders a bare EAP Success or Failure, which carry no type
// octet at all — the four-octet header is the whole packet.
func EncodeEAPResult(code, ident uint8) []byte {
	out := make([]byte, 4)
	out[0] = code
	out[1] = ident
	binary.BigEndian.PutUint16(out[2:4], 4)
	return out
}

// ParseEAP decodes one EAP packet. Data aliases the input.
func ParseEAP(buf []byte) (EAPPacket, error) {
	if len(buf) < 4 {
		return EAPPacket{}, errors.New("pulse: EAP packet shorter than its header")
	}
	length := int(binary.BigEndian.Uint16(buf[2:4]))
	if length < 4 || length > len(buf) {
		return EAPPacket{}, fmt.Errorf("pulse: EAP length %d out of range", length)
	}
	p := EAPPacket{Code: buf[0], Ident: buf[1]}
	if length == 4 {
		return p, nil // Success or Failure: no type, no data
	}
	if length < eapHeaderLen {
		return EAPPacket{}, errors.New("pulse: EAP packet has a length but no type")
	}
	p.Type = buf[4]
	if p.Type != EAPTypeExpanded {
		p.Data = buf[eapHeaderLen:length]
		return p, nil
	}
	if length < eapExpandedHeaderLen {
		return EAPPacket{}, errors.New("pulse: truncated expanded EAP header")
	}
	p.Expanded = true
	p.Vendor = binary.BigEndian.Uint32(buf[4:8]) & 0xffffff
	p.Subtype = binary.BigEndian.Uint32(buf[8:12])
	p.Data = buf[eapExpandedHeaderLen:length]
	return p, nil
}

// parseAuthMessage unwraps that envelope, rejecting an Auth Type this
// implementation does not speak rather than reading past it.
func parseAuthMessage(m Message) (EAPPacket, error) {
	if len(m.Payload) < 4 {
		return EAPPacket{}, errors.New("pulse: authentication message without an Auth Type")
	}
	if at := binary.BigEndian.Uint32(m.Payload[0:4]); at != AuthTypeJuniper1 {
		return EAPPacket{}, fmt.Errorf("pulse: unsupported IF-T/TLS Auth Type %#x", at)
	}
	if len(m.Payload) == 4 {
		// An empty challenge: the server's "begin" message carries no EAP at
		// all, which is legitimate and is how authentication starts.
		return EAPPacket{}, nil
	}
	return ParseEAP(m.Payload[4:])
}
