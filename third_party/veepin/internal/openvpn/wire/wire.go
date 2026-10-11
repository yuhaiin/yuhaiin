// Package wire is the OpenVPN packet codec: the opcode byte, session IDs, and
// the control-channel packet layout (the reliable messages that carry the TLS
// handshake and key negotiation).
//
// It is deliberately free of crypto and state, like its WireGuard sibling.
// OpenVPN multiplexes two channels over one UDP socket, told apart by the opcode
// in the first byte: control packets (reliable, TLS-bearing) are decoded here;
// data packets (the encrypted tunnel) are the data package's business, and this
// package only extracts their opcode for dispatch.
//
// The layouts are from OpenVPN's reliability and TLS-wrapping code (ssl_pkt.c,
// reliable.c). Every multi-byte field is big-endian (network byte order), unlike
// WireGuard's little-endian. This is the only place that touches raw offsets.
package wire

import (
	"encoding/binary"
	"errors"
)

// Opcodes occupy the high 5 bits of the first byte; the low 3 bits are the
// key_id. These are the P_* constants from OpenVPN's ssl_pkt.h.
const (
	PControlHardResetClientV1 = 1  // obsolete, not sent
	PControlHardResetServerV1 = 2  // obsolete, not sent
	PControlSoftResetV1       = 3  // key renegotiation reset
	PControlV1                = 4  // reliable control message (TLS payload)
	PACKV1                    = 5  // pure acknowledgement, carries no payload
	PDataV1                   = 6  // data channel, no peer-id
	PControlHardResetClientV2 = 7  // client session start
	PControlHardResetServerV2 = 8  // server session start
	PDataV2                   = 9  // data channel with a 3-byte peer-id
	PControlHardResetClientV3 = 10 // tls-crypt-v2 client start
	PControlWKCV1             = 11 // tls-crypt-v2 wrapped client key
)

// opcodeShift is how far the opcode sits above the 3-bit key_id.
const opcodeShift = 3

const (
	// SessionIDLen is the length of an OpenVPN session identifier: a random
	// 64-bit value each side picks to name its half of the connection.
	SessionIDLen = 8
	// PacketIDLen is the width of a control-channel message ID.
	PacketIDLen = 4
	// maxACKs bounds the acknowledgements packed into one control packet. The
	// count is a single octet, but OpenVPN never packs more than a handful; this
	// is a sanity cap on parsing attacker-supplied input.
	maxACKs = 255
)

var (
	// ErrMalformed reports a packet that is not a well-formed control message:
	// too short, or an ACK array that runs off the end. Inbound packets are
	// attacker-controlled, so this is a static error that never allocates.
	ErrMalformed = errors.New("wire: malformed control packet")
	// ErrShort reports a destination buffer too small to hold an encoded packet.
	ErrShort = errors.New("wire: buffer too short")
)

// SessionID is the 8-octet identifier each peer assigns to its side of a
// connection. The client picks its own in the hard-reset; the server's arrives
// in the hard-reset reply.
type SessionID [SessionIDLen]byte

// Opcode reads the opcode and key_id from a packet's first byte, reporting false
// if the packet is empty.
func Opcode(pkt []byte) (opcode, keyID uint8, ok bool) {
	if len(pkt) == 0 {
		return 0, 0, false
	}
	return pkt[0] >> opcodeShift, pkt[0] & 0x07, true
}

// firstByte packs an opcode and key_id into the wire's leading octet.
func firstByte(opcode, keyID uint8) byte {
	return opcode<<opcodeShift | keyID&0x07
}

// IsControl reports whether an opcode names a control-channel message (a
// reliable TLS-bearing packet or an ACK), as opposed to a data packet.
func IsControl(opcode uint8) bool {
	switch opcode {
	case PControlSoftResetV1, PControlV1, PACKV1,
		PControlHardResetClientV2, PControlHardResetServerV2,
		PControlHardResetClientV3, PControlWKCV1:
		return true
	default:
		return false
	}
}

// ControlPacket is a decoded control-channel message. The same struct serves
// every control opcode: a pure ACK (PACKV1) carries acknowledgements only, while
// the reliable opcodes (hard resets, PControlV1) additionally carry their own
// PacketID and a Payload — for a hard reset the payload is empty, and for
// PControlV1 it is a slice of the TLS stream.
type ControlPacket struct {
	Opcode    uint8
	KeyID     uint8
	SessionID SessionID // the sender's own session id

	// ACKs are the message IDs this packet acknowledges. RemoteSessionID is the
	// peer's session id, present on the wire only when ACKs is non-empty (an ack
	// names whose messages it acknowledges).
	ACKs            []uint32
	RemoteSessionID SessionID

	// PacketID and Payload are absent for PACKV1, which is not itself reliable.
	PacketID uint32
	Payload  []byte
}

// hasMessageBody reports whether this opcode carries its own packet ID and
// payload — true for every control opcode except the pure acknowledgement.
func (p *ControlPacket) hasMessageBody() bool {
	return p.Opcode != PACKV1
}

// Marshal encodes the control packet into dst, returning the written slice. dst
// must be at least MarshalLen bytes.
func (p *ControlPacket) Marshal(dst []byte) ([]byte, error) {
	if len(p.ACKs) > maxACKs {
		return nil, ErrMalformed
	}
	n := p.MarshalLen()
	if len(dst) < n {
		return nil, ErrShort
	}
	b := dst[:n]
	b[0] = firstByte(p.Opcode, p.KeyID)
	off := 1
	off += copy(b[off:], p.SessionID[:])

	b[off] = uint8(len(p.ACKs))
	off++
	for _, id := range p.ACKs {
		binary.BigEndian.PutUint32(b[off:], id)
		off += PacketIDLen
	}
	if len(p.ACKs) > 0 {
		off += copy(b[off:], p.RemoteSessionID[:])
	}

	if p.hasMessageBody() {
		binary.BigEndian.PutUint32(b[off:], p.PacketID)
		off += PacketIDLen
		off += copy(b[off:], p.Payload)
	}
	return b[:off], nil
}

// MarshalLen is the encoded size of the packet in octets.
func (p *ControlPacket) MarshalLen() int {
	n := 1 + SessionIDLen + 1 + len(p.ACKs)*PacketIDLen
	if len(p.ACKs) > 0 {
		n += SessionIDLen
	}
	if p.hasMessageBody() {
		n += PacketIDLen + len(p.Payload)
	}
	return n
}

// ParseControl decodes a control-channel packet. The opcode must already be
// known to be a control opcode (see IsControl); its bytes are copied out of pkt
// where fixed-size, and Payload aliases pkt, so the caller must not retain pkt
// past the payload's use.
func ParseControl(pkt []byte) (*ControlPacket, error) {
	opcode, keyID, ok := Opcode(pkt)
	if !ok || !IsControl(opcode) {
		return nil, ErrMalformed
	}
	p := &ControlPacket{Opcode: opcode, KeyID: keyID}
	off := 1
	if len(pkt) < off+SessionIDLen+1 {
		return nil, ErrMalformed
	}
	copy(p.SessionID[:], pkt[off:])
	off += SessionIDLen

	ackLen := int(pkt[off])
	off++
	need := ackLen * PacketIDLen
	if ackLen > 0 {
		need += SessionIDLen
	}
	if len(pkt) < off+need {
		return nil, ErrMalformed
	}
	if ackLen > 0 {
		p.ACKs = make([]uint32, ackLen)
		for i := range p.ACKs {
			p.ACKs[i] = binary.BigEndian.Uint32(pkt[off:])
			off += PacketIDLen
		}
		copy(p.RemoteSessionID[:], pkt[off:])
		off += SessionIDLen
	}

	if p.hasMessageBody() {
		if len(pkt) < off+PacketIDLen {
			return nil, ErrMalformed
		}
		p.PacketID = binary.BigEndian.Uint32(pkt[off:])
		off += PacketIDLen
		p.Payload = pkt[off:]
	}
	return p, nil
}
