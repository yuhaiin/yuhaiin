// Package sshtun is the wire glue for OpenSSH's layer-3 tunnel forwarding — the
// "tun@openssh.com" channel that `ssh -w` opens and `sshd` accepts under
// PermitTunnel. It is transport-agnostic: it only encodes the channel-open
// request and frames IP packets, so both the veepin client and server drive it
// over golang.org/x/crypto/ssh.
//
// Framing ([OpenSSH PROTOCOL], "tun@openssh.com"): the channel carries IP packets
// each prefixed with a 4-octet address family in network byte order. veepin's TUN
// is opened IFF_NO_PI (raw IP, no packet-info header), so Encode prepends the
// family and Decode strips it. The family values are the Linux AF_* numbers,
// which is what OpenSSH on Linux puts on the wire.
package sshtun

import (
	"encoding/binary"
	"errors"
	"io"
)

// ChannelType is the SSH channel type OpenSSH uses for tunnel forwarding.
const ChannelType = "tun@openssh.com"

// Tunnel modes ([OpenSSH PROTOCOL]). Only point-to-point (layer 3) is
// implemented; ethernet (layer 2 / TAP) is not.
const (
	ModePointToPoint = 1 // SSH_TUNMODE_POINTOPOINT
	ModeEthernet     = 2 // SSH_TUNMODE_ETHERNET
)

// TunIDAny lets the peer choose the tun unit number, matching `ssh -w any`.
const TunIDAny = 0x7fffffff

// Address-family header values (network byte order), the Linux AF_* numbers.
const (
	afInet  = 2
	afInet6 = 10
)

// headerLen is the 4-octet address-family prefix on each forwarded packet.
const headerLen = 4

// OpenData builds the CHANNEL_OPEN extra data for a tun@openssh.com channel: the
// tunnel mode and the requested remote unit number.
func OpenData(mode, unit uint32) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b[0:4], mode)
	binary.BigEndian.PutUint32(b[4:8], unit)
	return b
}

// ParseOpenData decodes the mode and unit from a tun@openssh.com CHANNEL_OPEN's
// extra data. A short buffer reports ok=false.
func ParseOpenData(b []byte) (mode, unit uint32, ok bool) {
	if len(b) < 8 {
		return 0, 0, false
	}
	return binary.BigEndian.Uint32(b[0:4]), binary.BigEndian.Uint32(b[4:8]), true
}

// Encode frames a raw IP packet for the channel: the address family (from the IP
// version) followed by the packet. It returns nil for a packet whose version is
// neither IPv4 nor IPv6.
func Encode(ipPacket []byte) []byte {
	af, ok := addressFamily(ipPacket)
	if !ok {
		return nil
	}
	out := make([]byte, headerLen+len(ipPacket))
	binary.BigEndian.PutUint32(out[:headerLen], af)
	copy(out[headerLen:], ipPacket)
	return out
}

// EncodePadded is Encode with zero filler appended, so the framed result reaches
// at least minTotal octets. A minTotal at or below the framed length pads
// nothing, which is what Encode passes.
//
// The filler is a whole number of 4-octet words, which is what lets ReadPacket
// recognise it: the address-family header is 00 00 00 02 or 00 00 00 0a, so a
// zero word can only be filler. The filler is rounded DOWN to a word rather than
// up, because the shaper's target is an MTU and overshooting it would be the one
// direction that costs something.
//
// It is inert to a stock OpenSSH peer for the usual reason: OpenSSH writes each
// channel message to its tun device in one call, and the kernel's IP stack
// delimits the real packet by the inner header's Total Length. The filler is
// never seen by anything above IP.
func EncodePadded(ipPacket []byte, minTotal int) []byte {
	frame := Encode(ipPacket)
	if frame == nil {
		return nil
	}
	fill := ((minTotal - len(frame)) / headerLen) * headerLen
	if fill <= 0 {
		return frame
	}
	return append(frame, make([]byte, fill)...)
}

// Decode strips the address-family header from a channel packet, returning the
// raw IP packet. A frame too short to hold the header reports ok=false.
func Decode(frame []byte) (ipPacket []byte, ok bool) {
	if len(frame) < headerLen {
		return nil, false
	}
	return frame[headerLen:], true
}

// ErrMalformed reports a framed packet whose IP header is unreadable.
var ErrMalformed = errors.New("sshtun: malformed packet")

// ReadPacket reads exactly one address-family-prefixed IP packet from a stream,
// returning the raw IP packet. An SSH channel is a byte stream, not a datagram
// channel, so packet boundaries are recovered from the IP length field rather
// than relying on SSH message boundaries: the 4-octet family header is skipped,
// then the IP total length delimits the packet.
//
// # Why the header is skipped a word at a time
//
// Shaping (dataplane/shape.go) appends zero filler after a packet, and on a byte
// stream that filler has to be distinguishable from the next packet's header or
// the framing desynchronises. It is, and cheaply: the family header is
// 00 00 00 02 or 00 00 00 0a, so a whole zero word can only be filler. Reading
// 4-octet words and discarding the zero ones lands exactly on the header, and
// the unshaped case still costs one read.
//
// This is why the filler is a whole number of 4-octet words (see EncodePadded).
// A ragged tail would need the reader to hunt for the non-zero octet inside a
// word, which is more code for no benefit -- the shaper's target is an MTU, and
// three octets either side of it changes nothing.
func ReadPacket(r io.Reader) ([]byte, error) {
	var af [headerLen]byte
	for {
		if _, err := io.ReadFull(r, af[:]); err != nil {
			return nil, err
		}
		if af != [headerLen]byte{} {
			break
		}
		// An all-zero word is shaping filler. Keep going.
	}
	// The family itself is not validated beyond being non-zero: Decode does not
	// check it either, and a peer that sends a family we do not recognise is
	// caught by the version nibble below, which is what actually determines how
	// the packet is framed.
	var first [1]byte
	if _, err := io.ReadFull(r, first[:]); err != nil {
		return nil, err
	}
	switch first[0] >> 4 {
	case 4:
		return readByLength(r, first[0], 20, 2)
	case 6:
		pkt, err := readByLength(r, first[0], 40, 4)
		return pkt, err
	default:
		return nil, ErrMalformed
	}
}

// readByLength reads a full IP packet given its first octet, the fixed header
// length, and the offset of the 16-bit length field. For IPv4 the length field
// is the total length; for IPv6 it is the payload length, added to the 40-octet
// header.
func readByLength(r io.Reader, first byte, hdrLen, lenOff int) ([]byte, error) {
	hdr := make([]byte, hdrLen)
	hdr[0] = first
	if _, err := io.ReadFull(r, hdr[1:]); err != nil {
		return nil, err
	}
	field := int(binary.BigEndian.Uint16(hdr[lenOff : lenOff+2]))

	total := field // IPv4: total length
	if hdrLen == 40 {
		total = 40 + field // IPv6: fixed header + payload length
	}
	if total < hdrLen {
		return nil, ErrMalformed
	}
	pkt := make([]byte, total)
	copy(pkt, hdr)
	if _, err := io.ReadFull(r, pkt[hdrLen:]); err != nil {
		return nil, err
	}
	return pkt, nil
}

// addressFamily returns the AF header value for an IP packet from its version
// nibble.
func addressFamily(ipPacket []byte) (uint32, bool) {
	if len(ipPacket) == 0 {
		return 0, false
	}
	switch ipPacket[0] >> 4 {
	case 4:
		return afInet, true
	case 6:
		return afInet6, true
	default:
		return 0, false
	}
}
