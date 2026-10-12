// Package wire is the SSTP packet codec ([MS-SSTP]): the 4-octet packet header
// that tells control packets from data packets, the control-message framing
// (message type plus a list of attributes), and the crypto-binding attribute
// layouts the handshake exchanges.
//
// SSTP runs over a TLS byte stream, so packets are length-delimited rather than
// datagram-framed: every packet's header carries its total length, and ReadPacket
// pulls exactly one packet off a stream. Every multi-byte field is big-endian.
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Version is the only SSTP version this implements (1.0).
const Version = 0x10

// HeaderLen is the fixed packet header: version, flags, and a 16-bit length.
const HeaderLen = 4

// flagControl is the low bit of the flags octet: set for a control packet, clear
// for a data packet.
const flagControl = 0x01

// maxPacketLen is the largest an SSTP packet can be: the length field is 12 bits.
const maxPacketLen = 0x0fff

// Control message types ([MS-SSTP] section 2.2).
const (
	MsgCallConnectRequest = 0x0001
	MsgCallConnectAck     = 0x0002
	MsgCallConnectNak     = 0x0003
	MsgCallConnected      = 0x0004
	MsgCallAbort          = 0x0005
	MsgCallDisconnect     = 0x0006
	MsgCallDisconnectAck  = 0x0007
	MsgEchoRequest        = 0x0008
	MsgEchoResponse       = 0x0009
)

// Attribute IDs ([MS-SSTP] section 2.2.1).
const (
	AttrNoError                = 0x00
	AttrEncapsulatedProtocolID = 0x01
	AttrStatusInfo             = 0x02
	AttrCryptoBinding          = 0x03
	AttrCryptoBindingReq       = 0x04
)

// ProtocolPPP is the only encapsulated protocol SSTP defines.
const ProtocolPPP = 0x0001

// Cert-hash protocol bitmask values ([MS-SSTP] section 2.2.7).
const (
	CertHashSHA1   = 0x01
	CertHashSHA256 = 0x02
)

// Fixed field sizes in the crypto-binding attributes.
const (
	NonceLen       = 32
	CertHashLen    = 32
	CompoundMACLen = 32
)

var (
	// ErrMalformed reports a packet that is not well formed: a bad version, a
	// length that disagrees with the buffer, or an attribute that runs off the end.
	ErrMalformed = errors.New("sstp: malformed packet")
	// ErrTooLong reports a payload that will not fit in SSTP's 12-bit length field.
	ErrTooLong = errors.New("sstp: packet too long")
)

// ReadPacket reads exactly one SSTP packet from a stream, returning whether it is
// a control packet and the bytes after the 4-octet header (a control message, or
// a data packet's payload).
func ReadPacket(r io.Reader) (control bool, body []byte, err error) {
	var hdr [HeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return false, nil, err
	}
	if hdr[0] != Version {
		return false, nil, fmt.Errorf("%w: version %#x", ErrMalformed, hdr[0])
	}
	control = hdr[1]&flagControl != 0
	length := int(binary.BigEndian.Uint16(hdr[2:4]) & maxPacketLen)
	if length < HeaderLen {
		return false, nil, ErrMalformed
	}
	body = make([]byte, length-HeaderLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return false, nil, err
	}
	return control, body, nil
}

// encodePacket frames a body as an SSTP packet with the given control flag.
func encodePacket(control bool, body []byte) ([]byte, error) {
	total := HeaderLen + len(body)
	if total > maxPacketLen {
		return nil, ErrTooLong
	}
	out := make([]byte, total)
	out[0] = Version
	if control {
		out[1] = flagControl
	}
	binary.BigEndian.PutUint16(out[2:4], uint16(total))
	copy(out[HeaderLen:], body)
	return out, nil
}

// EncodeData wraps a payload (a PPP frame) in an SSTP data packet.
func EncodeData(payload []byte) ([]byte, error) {
	return encodePacket(false, payload)
}

// Attribute is one control-message attribute: its ID and value (the value
// excludes the 4-octet attribute header).
type Attribute struct {
	ID    byte
	Value []byte
}

// encodeAttribute frames one attribute: a reserved octet, the ID, a 16-bit
// length covering the whole attribute, then the value.
func encodeAttribute(a Attribute) []byte {
	total := 4 + len(a.Value)
	out := make([]byte, total)
	out[0] = 0 // reserved
	out[1] = a.ID
	binary.BigEndian.PutUint16(out[2:4], uint16(total))
	copy(out[4:], a.Value)
	return out
}

// EncodeControl builds a control packet from a message type and its attributes.
func EncodeControl(msgType uint16, attrs []Attribute) ([]byte, error) {
	body := make([]byte, 4)
	binary.BigEndian.PutUint16(body[0:2], msgType)
	binary.BigEndian.PutUint16(body[2:4], uint16(len(attrs)))
	for _, a := range attrs {
		body = append(body, encodeAttribute(a)...)
	}
	return encodePacket(true, body)
}

// ControlMessage is a decoded control packet.
type ControlMessage struct {
	Type       uint16
	Attributes []Attribute
}

// ParseControl decodes a control message body (the bytes after the packet
// header): the message type, the attribute count, and the attributes.
func ParseControl(body []byte) (ControlMessage, error) {
	if len(body) < 4 {
		return ControlMessage{}, ErrMalformed
	}
	msg := ControlMessage{Type: binary.BigEndian.Uint16(body[0:2])}
	num := int(binary.BigEndian.Uint16(body[2:4]))
	b := body[4:]
	for range num {
		if len(b) < 4 {
			return ControlMessage{}, ErrMalformed
		}
		length := int(binary.BigEndian.Uint16(b[2:4]) & maxPacketLen)
		if length < 4 || length > len(b) {
			return ControlMessage{}, ErrMalformed
		}
		msg.Attributes = append(msg.Attributes, Attribute{ID: b[1], Value: append([]byte(nil), b[4:length]...)})
		b = b[length:]
	}
	return msg, nil
}

// Attribute returns the first attribute with the given ID, or false.
func (m ControlMessage) Attribute(id byte) (Attribute, bool) {
	for _, a := range m.Attributes {
		if a.ID == id {
			return a, true
		}
	}
	return Attribute{}, false
}
