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
	opFailure   mschapOpcode = 4
	// opChangePassword = 7 (not supported)
)

// mschapChallenge builds the type-data for an MSCHAPv2 Challenge request
// (RFC 2759 section 6):
//
//	OpCode(1) | MS-CHAPv2-ID(1) | MS-Length(2) | Value-Size(1) |
//	Challenge(16) | Name(...)
func mschapChallenge(id uint8, challenge [16]byte, name string) []byte {
	body := make([]byte, 5)
	body[0] = byte(opChallenge)
	body[1] = id
	msLen := 5 + 1 + 16 + len(name)
	binary.BigEndian.PutUint16(body[2:4], uint16(msLen))
	body[4] = 16
	body = append(body, challenge[:]...)
	body = append(body, []byte(name)...)
	return body
}

// mschapResponseFields holds the parsed fields of an MSCHAPv2 Response.
type mschapResponseFields struct {
	ID            uint8
	PeerChallenge [16]byte
	NTResponse    [24]byte
	Name          string
}

// parseMSCHAPResponse parses the type-data of an MSCHAPv2 Response
// (RFC 2759 section 7):
//
//	OpCode(1)=2 | MS-CHAPv2-ID(1) | MS-Length(2) | Value-Size(1)=49 |
//	Response{ PeerChallenge(16) | Reserved(8) | NTResponse(24) | Flags(1) } |
//	Name(...)
func parseMSCHAPResponse(data []byte) (mschapResponseFields, error) {
	var f mschapResponseFields
	if len(data) < 5 || mschapOpcode(data[0]) != opResponse {
		return f, fmt.Errorf("eap: not an MSCHAPv2 response")
	}
	f.ID = data[1]
	valueSize := int(data[4])
	if valueSize != 49 {
		return f, fmt.Errorf("eap: bad MSCHAPv2 value-size %d", valueSize)
	}
	if len(data) < 5+49 {
		return f, fmt.Errorf("eap: MSCHAPv2 response too short")
	}
	resp := data[5 : 5+49]
	copy(f.PeerChallenge[:], resp[0:16])
	// resp[16:24] reserved
	copy(f.NTResponse[:], resp[24:48])
	// resp[48] flags
	f.Name = string(data[5+49:])
	return f, nil
}

// mschapSuccess builds the type-data for an MSCHAPv2 Success request
// (RFC 2759 section 8): OpCode(1)=3 | MS-CHAPv2-ID(1) | MS-Length(2) |
// "S=<40 hex>" message.
func mschapSuccess(id uint8, authResponse []byte) []byte {
	msg := "S=" + upperHex(authResponse)
	body := make([]byte, 4)
	body[0] = byte(opSuccess)
	body[1] = id
	binary.BigEndian.PutUint16(body[2:4], uint16(4+len(msg)))
	return append(body, []byte(msg)...)
}

// mschapFailure builds an MSCHAPv2 Failure request with an error string.
func mschapFailure(id uint8, message string) []byte {
	body := make([]byte, 4)
	body[0] = byte(opFailure)
	body[1] = id
	binary.BigEndian.PutUint16(body[2:4], uint16(4+len(message)))
	return append(body, []byte(message)...)
}

func upperHex(b []byte) string {
	const hexDigits = "0123456789ABCDEF"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexDigits[c>>4]
		out[i*2+1] = hexDigits[c&0x0f]
	}
	return string(out)
}
