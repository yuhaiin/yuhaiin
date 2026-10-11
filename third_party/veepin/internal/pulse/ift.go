// Package pulse implements the Ivanti Connect Secure (formerly Pulse Connect
// Secure, formerly Juniper) VPN protocol: IF-T/TLS framing over an ordinary TLS
// connection, EAP inside it for authentication, a TLV configuration exchange,
// and either RFC 4303 ESP over UDP or the same IF-T/TLS connection for data.
//
// It is the only protocol in veepin whose authentication is EAP over a stream
// transport rather than over a datagram one, and the only one whose ESP keys are
// pushed by the server in a fixed-layout binary packet rather than negotiated.
//
// There is no specification. Every offset here comes from openconnect's
// pulse.c — the only independent implementation — and from the packet dumps its
// comments preserve. Where openconnect enforces a value, veepin's server emits
// exactly that value, because openconnect is the peer the interop tests use.
package pulse

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// The IF-T/TLS header (TCG TNC IF-T Protocol Bindings for TLS, section 3.5):
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|  reserved     |            Message Type Vendor ID             |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                        Message Type                           |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                      Message Length                           |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                     Message Identifier                        |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Everything is big-endian, and Message Length counts the header itself. The
// vendor ID occupies the low 24 bits of the first word; the top octet is
// reserved and is zero in practice, which is why openconnect masks it off.

// HeaderLen is the fixed IF-T/TLS header size in octets.
const HeaderLen = 16

// Vendor IDs. TCG owns the protocol wrapper; Juniper owns everything carried
// inside it, and a second Juniper enterprise number owns the AVPs.
const (
	VendorTCG      = 0x5597
	VendorJuniper  = 0x0a4c
	VendorJuniper2 = 0x0583
)

// Message types in the TCG vendor space (the authentication wrapper).
const (
	TypeVersionRequest  = 1
	TypeVersionResponse = 2
	TypeAuthRequest     = 3
	TypeAuthSelection   = 4
	TypeAuthChallenge   = 5
	TypeAuthResponse    = 6
	TypeAuthSuccess     = 7
)

// Message types in the Juniper vendor space (configuration and data).
const (
	// TypeConfig carries the configuration and ESP-keying packets, told apart
	// by a signature word at offset 0x10 of the payload.
	TypeConfig = 1
	// TypeData carries one bare IP packet.
	TypeData = 4
	// TypeControl carries a NUL-terminated "key=value" line; the client sends
	// "ncmo=1" on it to say it has the ESP keys and the server may start using
	// them.
	TypeControl = 5
	// TypeClientInfo carries the client's hostname and capabilities as a
	// NUL-terminated line, before authentication begins.
	TypeClientInfo = 0x88
	// TypeClose ends the session with a reason string.
	TypeClose = 0x89
)

// AuthTypeJuniper1 is the IF-T/TLS Auth Type word that opens every
// authentication message's payload: the Juniper vendor ID in the high 24 bits
// and a type of 1 in the low octet.
const AuthTypeJuniper1 = (VendorJuniper << 8) | 1

// Framing errors, returned as static values so the reject path on the data
// carrier allocates nothing per packet.
var (
	ErrShortMessage = errors.New("pulse: message shorter than its header")
	ErrBadLength    = errors.New("pulse: message length outside the buffer")
)

// Message is one decoded IF-T/TLS message. Payload aliases the input buffer:
// parsing copies nothing, which is what keeps the inbound data path free of
// per-packet allocation.
type Message struct {
	Vendor  uint32
	Type    uint32
	ID      uint32
	Payload []byte
}

// EncodeMessage renders one IF-T/TLS message. It allocates once.
func EncodeMessage(vendor, msgType, id uint32, payload []byte) []byte {
	out := make([]byte, HeaderLen+len(payload))
	putHeader(out, vendor, msgType, id, len(out))
	copy(out[HeaderLen:], payload)
	return out
}

// EncodeData wraps one bare IP packet as a Juniper data message.
func EncodeData(id uint32, ipPacket []byte) []byte {
	return EncodeMessage(VendorJuniper, TypeData, id, ipPacket)
}

func putHeader(out []byte, vendor, msgType, id uint32, total int) {
	binary.BigEndian.PutUint32(out[0:4], vendor&0xffffff)
	binary.BigEndian.PutUint32(out[4:8], msgType)
	binary.BigEndian.PutUint32(out[8:12], uint32(total))
	binary.BigEndian.PutUint32(out[12:16], id)
}

// ParseMessage decodes one message from the front of buf, returning it and
// whatever follows. The returned payload is a subslice of buf, so it stays
// valid only as long as buf does — and this parse allocates nothing.
func ParseMessage(buf []byte) (m Message, rest []byte, err error) {
	if len(buf) < HeaderLen {
		return Message{}, nil, ErrShortMessage
	}
	total := binary.BigEndian.Uint32(buf[8:12])
	if total < HeaderLen || uint64(total) > uint64(len(buf)) {
		return Message{}, nil, ErrBadLength
	}
	return Message{
		// The top octet of the first word is reserved; masking it rather than
		// rejecting a non-zero value is what openconnect does, and a peer that
		// sets it is otherwise speaking the protocol correctly.
		Vendor:  binary.BigEndian.Uint32(buf[0:4]) & 0xffffff,
		Type:    binary.BigEndian.Uint32(buf[4:8]),
		ID:      binary.BigEndian.Uint32(buf[12:16]),
		Payload: buf[HeaderLen:total],
	}, buf[total:], nil
}

// maxMessage bounds one IF-T/TLS message. openconnect reads into a 16 KiB
// buffer and refuses anything larger, so nothing legitimate exceeds it; the
// bound is what stops a peer's length field from making the reader allocate.
const maxMessage = 16384

// ReadMessage reads exactly one message from a stream, which is what the
// control plane does — the data path reads in batches instead.
//
// The returned payload is freshly allocated, because a stream reader cannot
// hand out a view of a buffer it is about to reuse.
func ReadMessage(r io.Reader) (Message, error) {
	var hdr [HeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Message{}, err
	}
	total := binary.BigEndian.Uint32(hdr[8:12])
	if total < HeaderLen {
		return Message{}, ErrShortMessage
	}
	if total > maxMessage {
		return Message{}, fmt.Errorf("pulse: message of %d octets exceeds the %d-octet limit", total, maxMessage)
	}
	payload := make([]byte, int(total)-HeaderLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return Message{}, err
	}
	return Message{
		Vendor:  binary.BigEndian.Uint32(hdr[0:4]) & 0xffffff,
		Type:    binary.BigEndian.Uint32(hdr[4:8]),
		ID:      binary.BigEndian.Uint32(hdr[12:16]),
		Payload: payload,
	}, nil
}

// EncodeLine renders one of the NUL-terminated "key=value" control messages:
// the client-information packet before authentication, and the "ncmo=1" that
// arms ESP afterwards.
func EncodeLine(vendor, msgType, id uint32, line string) []byte {
	payload := make([]byte, len(line)+1)
	copy(payload, line)
	return EncodeMessage(vendor, msgType, id, payload)
}

// Data-path sentinels, pre-built so a link that is tearing down or being fed
// garbage allocates nothing on the way out.
var (
	errOversizedMessage = errors.New("pulse: peer sent a message larger than the buffer allows")
	errPeerClosed       = errors.New("pulse: the peer closed the session")
)
