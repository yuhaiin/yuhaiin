package nebula

// The wire header.
//
// Every nebula datagram starts with the same fixed 16 octets — no options, no
// variable-length fields, nothing to parse defensively beyond a length check:
//
//	 0                                                                     31
//	|-----------------------------------------------------------------------|
//	| Version (u4) | Type (u4) |  Subtype (u8)  |      Reserved (u16)        |
//	|-----------------------------------------------------------------------|
//	|                        Remote index (u32)                             |
//	|-----------------------------------------------------------------------|
//	|                     Message counter (u64)                             |
//	|-----------------------------------------------------------------------|
//	|                            payload...                                 |
//
// The remote index is the peer's identifier for the tunnel, chosen by the peer
// during the handshake and echoed back on every packet. Demultiplexing on it
// rather than on the source address is what lets a host survive a NAT rebinding
// or a roam between networks without renegotiating.
//
// The header is not merely a prefix: the data path passes these 16 octets to
// the AEAD as additional data, so a forged type, index or counter fails
// authentication rather than being silently acted upon.

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// headerLen is the fixed size of the nebula header.
const headerLen = 16

// Overhead is what nebula adds to an inner packet on the wire: the fixed header,
// which is authenticated as additional data rather than encrypted, and the AEAD
// tag appended to the ciphertext. It is exported so the facade can size the
// interface MTU from the wire format rather than from a literal.
const Overhead = headerLen + tagSize

// headerVersion is the only protocol version defined.
const headerVersion uint8 = 1

// messageType identifies what a datagram carries.
type messageType uint8

const (
	typeHandshake   messageType = 0
	typeMessage     messageType = 1
	typeRecvError   messageType = 2
	typeLightHouse  messageType = 3
	typeTest        messageType = 4
	typeCloseTunnel messageType = 5
	typeControl     messageType = 6
)

func (t messageType) String() string {
	switch t {
	case typeHandshake:
		return "handshake"
	case typeMessage:
		return "message"
	case typeRecvError:
		return "recvError"
	case typeLightHouse:
		return "lightHouse"
	case typeTest:
		return "test"
	case typeCloseTunnel:
		return "closeTunnel"
	case typeControl:
		return "control"
	default:
		return fmt.Sprintf("messageType(%d)", uint8(t))
	}
}

// messageSubType qualifies a message type.
type messageSubType uint8

const (
	subTypeNone  messageSubType = 0
	subTypeRelay messageSubType = 1

	// Test messages use the subtype to distinguish request from reply.
	subTypeTestRequest messageSubType = 0
	subTypeTestReply   messageSubType = 1

	// Handshake messages name the Noise pattern. The constant is spelled
	// IXPSK0 in nebula, but the exchange is plain Noise_IX — see noise.go.
	subTypeHandshakeIXPSK0 messageSubType = 0
)

var errShortHeader = errors.New("nebula: datagram is shorter than the header")

// header is a parsed nebula header.
type header struct {
	Version        uint8
	Type           messageType
	Subtype        messageSubType
	Reserved       uint16
	RemoteIndex    uint32
	MessageCounter uint64
}

// encode appends the header to b.
func (h header) encode(b []byte) []byte {
	var raw [headerLen]byte
	raw[0] = h.Version<<4 | uint8(h.Type)&0x0f
	raw[1] = uint8(h.Subtype)
	binary.BigEndian.PutUint16(raw[2:4], h.Reserved)
	binary.BigEndian.PutUint32(raw[4:8], h.RemoteIndex)
	binary.BigEndian.PutUint64(raw[8:16], h.MessageCounter)
	return append(b, raw[:]...)
}

// parseHeader reads the header from a datagram.
func parseHeader(b []byte) (header, error) {
	if len(b) < headerLen {
		return header{}, errShortHeader
	}
	return header{
		Version:        b[0] >> 4 & 0x0f,
		Type:           messageType(b[0] & 0x0f),
		Subtype:        messageSubType(b[1]),
		Reserved:       binary.BigEndian.Uint16(b[2:4]),
		RemoteIndex:    binary.BigEndian.Uint32(b[4:8]),
		MessageCounter: binary.BigEndian.Uint64(b[8:16]),
	}, nil
}
