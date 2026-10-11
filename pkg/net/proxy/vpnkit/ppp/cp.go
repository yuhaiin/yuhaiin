package ppp

import "encoding/binary"

// Control-protocol codes (RFC 1661 section 5), shared by LCP and IPCP.
const (
	codeConfigureRequest = 1
	codeConfigureAck     = 2
	codeConfigureNak     = 3
	codeConfigureReject  = 4
	codeTerminateRequest = 5
	codeTerminateAck     = 6
	codeEchoRequest      = 9
	codeEchoReply        = 10
)

// cpPacket is a control-protocol packet: a code, an identifier that pairs a
// reply with its request, and a body (the options for Configure-* packets).
type cpPacket struct {
	Code byte
	ID   byte
	Body []byte
}

// parseCP decodes a control-protocol packet, validating the length field
// against the buffer.
func parseCP(b []byte) (cpPacket, bool) {
	if len(b) < 4 {
		return cpPacket{}, false
	}
	length := int(binary.BigEndian.Uint16(b[2:4]))
	if length < 4 || length > len(b) {
		return cpPacket{}, false
	}
	return cpPacket{Code: b[0], ID: b[1], Body: b[4:length]}, true
}

// marshal encodes a control-protocol packet, filling in the length.
func (p cpPacket) marshal() []byte {
	out := make([]byte, 4+len(p.Body))
	out[0] = p.Code
	out[1] = p.ID
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	copy(out[4:], p.Body)
	return out
}

// option is one configuration option: a type and its value (the length octet is
// implicit in the value's size when encoded).
type option struct {
	Type  byte
	Value []byte
}

// parseOptions decodes a Configure-* option list. It returns false on a
// malformed option (a length that runs off the end or is under the 2-octet
// header).
func parseOptions(b []byte) ([]option, bool) {
	var opts []option
	for len(b) > 0 {
		if len(b) < 2 {
			return nil, false
		}
		length := int(b[1])
		if length < 2 || length > len(b) {
			return nil, false
		}
		opts = append(opts, option{Type: b[0], Value: append([]byte(nil), b[2:length]...)})
		b = b[length:]
	}
	return opts, true
}

// marshalOptions encodes an option list with each option's length octet.
func marshalOptions(opts []option) []byte {
	var out []byte
	for _, o := range opts {
		out = append(out, o.Type, byte(2+len(o.Value)))
		out = append(out, o.Value...)
	}
	return out
}
