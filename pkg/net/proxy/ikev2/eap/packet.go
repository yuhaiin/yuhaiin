package eap

import (
	"encoding/binary"
	"fmt"
)

// Code is the EAP packet code (RFC 3748 section 4).
type Code uint8

const (
	CodeRequest  Code = 1
	CodeResponse Code = 2
	CodeSuccess  Code = 3
	CodeFailure  Code = 4
)

// Type is the EAP method type (RFC 3748 section 5).
type Type uint8

const (
	TypeIdentity Type = 1
	TypeNotify   Type = 2
	TypeNak      Type = 3
	TypeMSCHAPv2 Type = 26
)

// Packet is a decoded EAP packet.
type Packet struct {
	Code       Code
	Identifier uint8
	Type       Type   // valid for Request/Response
	Data       []byte // type-data (after the Type octet)
}

// Marshal encodes an EAP packet. Success/Failure carry no type or data.
func (p Packet) Marshal() []byte {
	if p.Code == CodeSuccess || p.Code == CodeFailure {
		out := make([]byte, 4)
		out[0] = byte(p.Code)
		out[1] = p.Identifier
		binary.BigEndian.PutUint16(out[2:4], 4)
		return out
	}
	total := 5 + len(p.Data)
	out := make([]byte, 5)
	out[0] = byte(p.Code)
	out[1] = p.Identifier
	binary.BigEndian.PutUint16(out[2:4], uint16(total))
	out[4] = byte(p.Type)
	return append(out, p.Data...)
}

// Parse decodes an EAP packet.
func Parse(buf []byte) (Packet, error) {
	if len(buf) < 4 {
		return Packet{}, fmt.Errorf("eap: packet too short")
	}
	p := Packet{
		Code:       Code(buf[0]),
		Identifier: buf[1],
	}
	length := int(binary.BigEndian.Uint16(buf[2:4]))
	if length < 4 || length > len(buf) {
		return Packet{}, fmt.Errorf("eap: bad length %d", length)
	}
	if p.Code == CodeSuccess || p.Code == CodeFailure {
		return p, nil
	}
	if length < 5 {
		return Packet{}, fmt.Errorf("eap: request/response missing type")
	}
	p.Type = Type(buf[4])
	p.Data = append([]byte(nil), buf[5:length]...)
	return p, nil
}

// --- MSCHAPv2 opcodes (RFC 2759 section 5) ---

type mschapOpcode uint8

const (
	opChallenge mschapOpcode = 1
	opResponse  mschapOpcode = 2
	opSuccess   mschapOpcode = 3
	// opChangePassword = 7 (not supported)
)
