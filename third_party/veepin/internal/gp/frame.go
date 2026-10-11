// Package gp implements the Palo Alto Networks GlobalProtect SSL VPN protocol:
// the HTTPS authentication and configuration exchange, and both of the data
// paths that exchange sets up.
//
// It is unusual among the SSL VPNs here in two ways. There is no key exchange at
// all — the gateway hands the client its ESP keys and SPIs inside the
// configuration XML, over the authenticated HTTPS channel — and there is no PPP:
// the tunnel carries bare layer-3 packets under a 16-octet header. So the parts
// worth reading are small: this file (the framing), config.go (the XML, including
// the keying material) and esp.go (the RFC 4303 data path, which is
// internal/ikev2/esp with the keys plugged in).
//
// The two data paths are mutually exclusive by design. Activating the SSL tunnel
// invalidates the ESP SPIs the same configuration handed out, which is why a
// client that wants ESP must not open the tunnel endpoint first, and why the
// fallback runs in that direction only.
package gp

import (
	"encoding/binary"
	"errors"
	"io"
)

// Every packet on the SSL tunnel carries a 16-octet header:
//
//	0        4          6        8            12          16
//	+--------+----------+--------+------------+-----------+--------------+
//	|1a2b3c4d|ethertype |len BE  | kind LE32  |  zero32   | layer-3 body |
//	+--------+----------+--------+------------+-----------+--------------+
//
// len counts the body alone. kind is 1 for a data packet and 0 for the
// keepalive/DPD packet, which carries no body. The two trailing words are
// little-endian where everything before them is big-endian; that is Palo Alto's
// choice, reproduced here because the reference client checks it.
const (
	frameHeaderLen = 16
	// maxFramePayload bounds one layer-3 packet this code will buffer. The length
	// field is 16 bits, so this is its ceiling rather than a policy — it stops a
	// hostile length from forcing an unbounded allocation.
	maxFramePayload = 1<<16 - 1
)

// frameMagic is the constant first word of every packet.
const frameMagic = 0x1a2b3c4d

// Packet kinds, carried little-endian at octets 8..11.
const (
	// KindData marks a packet carrying a layer-3 body.
	KindData = 1
	// KindKeepalive marks the empty dead-peer-detection packet. Both roles send
	// it and both answer it, which is what makes it a liveness probe.
	KindKeepalive = 0
)

// EtherType values the tunnel carries. GlobalProtect names the payload with an
// Ethernet type even though no Ethernet header is present.
const (
	EtherTypeIPv4 = 0x0800
	EtherTypeIPv6 = 0x86dd
)

var (
	// ErrShortFrame reports a buffer too short to hold the header, or a header
	// whose announced body has not all arrived. A caller streaming records needs
	// this told apart from a malformed one: it means "read more", not "give up".
	ErrShortFrame = errors.New("gp: packet shorter than its header")
	// ErrBadMagic reports the leading 1a2b3c4d being wrong — usually a desynced
	// stream rather than a short read.
	ErrBadMagic = errors.New("gp: packet magic is not 1a2b3c4d")
	// ErrFrameTooLarge reports a body larger than the buffer ceiling.
	ErrFrameTooLarge = errors.New("gp: packet exceeds the maximum")
)

// Frame is one decoded tunnel packet. Payload aliases the buffer it was parsed
// from, so a caller that keeps it past the next read must copy it.
type Frame struct {
	EtherType uint16
	Kind      uint32
	Payload   []byte
}

// IsKeepalive reports whether the packet is the empty liveness probe rather than
// carrying traffic.
func (f Frame) IsKeepalive() bool { return f.Kind == KindKeepalive || len(f.Payload) == 0 }

// EncodeFrame wraps a layer-3 packet in the GlobalProtect header. etherType names
// the payload; use EtherTypeFor to derive it from the packet itself.
func EncodeFrame(etherType uint16, payload []byte) []byte {
	out := make([]byte, frameHeaderLen+len(payload))
	binary.BigEndian.PutUint32(out[0:4], frameMagic)
	binary.BigEndian.PutUint16(out[4:6], etherType)
	binary.BigEndian.PutUint16(out[6:8], uint16(len(payload)))
	binary.LittleEndian.PutUint32(out[8:12], KindData)
	// out[12:16] is already zero.
	copy(out[frameHeaderLen:], payload)
	return out
}

// EncodeKeepalive renders the empty dead-peer-detection packet.
func EncodeKeepalive() []byte {
	var out [frameHeaderLen]byte
	binary.BigEndian.PutUint32(out[0:4], frameMagic)
	binary.BigEndian.PutUint16(out[4:6], EtherTypeIPv4)
	// Length, kind and the trailing word are all zero, which is what marks it.
	return out[:]
}

// ParseFrame reads the header at the front of buf and returns the packet and the
// bytes after it. Payload is a subslice of buf, so parsing allocates nothing.
func ParseFrame(buf []byte) (f Frame, rest []byte, err error) {
	if len(buf) < frameHeaderLen {
		return Frame{}, buf, ErrShortFrame
	}
	if binary.BigEndian.Uint32(buf[0:4]) != frameMagic {
		return Frame{}, buf, ErrBadMagic
	}
	plen := int(binary.BigEndian.Uint16(buf[6:8]))
	if plen > maxFramePayload {
		return Frame{}, buf, ErrFrameTooLarge
	}
	if len(buf) < frameHeaderLen+plen {
		// The header is valid but the body has not all arrived yet.
		return Frame{}, buf, ErrShortFrame
	}
	return Frame{
		EtherType: binary.BigEndian.Uint16(buf[4:6]),
		Kind:      binary.LittleEndian.Uint32(buf[8:12]),
		Payload:   buf[frameHeaderLen : frameHeaderLen+plen],
	}, buf[frameHeaderLen+plen:], nil
}

// ReadFrame reads exactly one packet from r. It reads the 16-octet header first,
// then the body its length announces, so it never consumes into the next packet —
// which a stream carrier requires.
func ReadFrame(r io.Reader) (Frame, error) {
	var hdr [frameHeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, err
	}
	if binary.BigEndian.Uint32(hdr[0:4]) != frameMagic {
		return Frame{}, ErrBadMagic
	}
	plen := int(binary.BigEndian.Uint16(hdr[6:8]))
	if plen > maxFramePayload {
		return Frame{}, ErrFrameTooLarge
	}
	f := Frame{
		EtherType: binary.BigEndian.Uint16(hdr[4:6]),
		Kind:      binary.LittleEndian.Uint32(hdr[8:12]),
	}
	if plen == 0 {
		return f, nil
	}
	f.Payload = make([]byte, plen)
	if _, err := io.ReadFull(r, f.Payload); err != nil {
		return Frame{}, err
	}
	return f, nil
}

// EtherTypeFor names an IP packet by its version nibble. It reports false for a
// buffer that is not an IP packet at all, which a caller drops rather than
// labelling wrongly.
func EtherTypeFor(pkt []byte) (uint16, bool) {
	if len(pkt) == 0 {
		return 0, false
	}
	switch pkt[0] >> 4 {
	case 4:
		return EtherTypeIPv4, true
	case 6:
		return EtherTypeIPv6, true
	default:
		return 0, false
	}
}
