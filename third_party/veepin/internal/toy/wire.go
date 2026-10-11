// Package toy implements TOY, a teaching protocol.
//
// TOY PROVIDES NO SECURITY. It exists so the *shape* of a veepin protocol can
// be read in one sitting: a handshake that produces a client.Result, a framed
// data path built on dataplane.Pump, and both roles registered with the client
// registry. Its cryptography is deliberately worthless — a repeating XOR
// keystream and a non-cryptographic hash — and SPEC.md sets out exactly how and
// why it fails.
//
// If you are adding a real protocol to veepin, this package is the smallest
// complete example to copy the structure from. Copy the structure, not the
// cryptography.
//
// The full wire format is in SPEC.md, alongside this file. It is written to be
// reimplementable, and the interop harness proves that it is by talking to an
// independent Python implementation of that document.
package toy

// The wire format: a fixed 12-octet header and a handful of message bodies.
//
// Everything is big-endian and fixed-width, so parsing is bounds checks and
// slicing. Every parse function here takes attacker-controlled input and must
// report failure rather than panic.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
)

// Wire constants. These are the protocol; changing one is a format change.
const (
	// HeaderLen is the fixed header size.
	HeaderLen = 12
	// Version is the only protocol version defined.
	Version = 1
	// DefaultPort is the UDP port a TOY server listens on.
	DefaultPort = 5555

	// NonceLen is the size of each side's handshake nonce.
	NonceLen = 8
	// TagLen is the size of the packet tag, and of the auth proof.
	TagLen = 8
	// KeyLen is the size of the derived key, and therefore the keystream period.
	KeyLen = 32
)

// Overhead is what TOY adds to an inner packet on the wire: the header the tag
// covers, and the tag itself. The facade sizes the interface MTU from this
// rather than from a literal, so a header change cannot leave the MTU stale.
const Overhead = HeaderLen + TagLen

// magic is the first three octets of every datagram.
var magic = [3]byte{'T', 'O', 'Y'}

// MsgType identifies what a datagram carries.
type MsgType uint8

const (
	MsgHello     MsgType = 0x01
	MsgChallenge MsgType = 0x02
	MsgAuth      MsgType = 0x03
	MsgWelcome   MsgType = 0x04
	MsgReject    MsgType = 0x05
	MsgData      MsgType = 0x06
	MsgKeepalive MsgType = 0x07
	MsgBye       MsgType = 0x08
)

func (t MsgType) String() string {
	switch t {
	case MsgHello:
		return "HELLO"
	case MsgChallenge:
		return "CHALLENGE"
	case MsgAuth:
		return "AUTH"
	case MsgWelcome:
		return "WELCOME"
	case MsgReject:
		return "REJECT"
	case MsgData:
		return "DATA"
	case MsgKeepalive:
		return "KEEPALIVE"
	case MsgBye:
		return "BYE"
	default:
		return fmt.Sprintf("MsgType(0x%02x)", uint8(t))
	}
}

// Errors the codec reports. They are distinguishable so a caller can tell "not
// ours" (worth ignoring silently) from "ours but broken" (worth logging).
var (
	ErrNotTOY    = errors.New("toy: datagram is not TOY")
	ErrVersion   = errors.New("toy: unsupported protocol version")
	ErrShort     = errors.New("toy: datagram is truncated")
	ErrMalformed = errors.New("toy: message body is malformed")

	// ErrAuth reports a REJECT whose reason means the credentials were refused.
	// The facade maps it onto client.ErrAuth so `veepin connect -retry` stops
	// instead of replaying a wrong secret, which is the same contract every
	// real protocol in this tree honours -- TOY is the worked example, so it
	// honours it too rather than leaving the reader a shape to copy that is
	// missing a piece.
	ErrAuth = errors.New("toy: authentication failed")
)

// Header is the parsed fixed header.
type Header struct {
	Type    MsgType
	Flags   uint8
	Session uint16
	Counter uint32
}

// AppendHeader writes the header to b.
func AppendHeader(b []byte, h Header) []byte {
	var raw [HeaderLen]byte
	copy(raw[0:3], magic[:])
	raw[3] = Version
	raw[4] = byte(h.Type)
	raw[5] = h.Flags
	binary.BigEndian.PutUint16(raw[6:8], h.Session)
	binary.BigEndian.PutUint32(raw[8:12], h.Counter)
	return append(b, raw[:]...)
}

// ParseHeader reads the header and returns it with the remaining body.
func ParseHeader(pkt []byte) (Header, []byte, error) {
	if len(pkt) < HeaderLen {
		return Header{}, nil, ErrShort
	}
	if pkt[0] != magic[0] || pkt[1] != magic[1] || pkt[2] != magic[2] {
		// Not addressed to us at all: a stray datagram, a port scan, another
		// protocol on a shared socket. Callers ignore this silently.
		return Header{}, nil, ErrNotTOY
	}
	if pkt[3] != Version {
		return Header{}, nil, ErrVersion
	}
	return Header{
		Type:    MsgType(pkt[4]),
		Flags:   pkt[5],
		Session: binary.BigEndian.Uint16(pkt[6:8]),
		Counter: binary.BigEndian.Uint32(pkt[8:12]),
	}, pkt[HeaderLen:], nil
}

// SessionOf reads the session ID without parsing the rest, for demux. It
// reports false for anything that is not a well-formed TOY datagram.
//
// This is what dataplane.Pump uses to find the tunnel an inbound packet belongs
// to — by session ID, never by source address, so a peer that is re-NATed keeps
// working.
func SessionOf(pkt []byte) (uint32, bool) {
	h, _, err := ParseHeader(pkt)
	if err != nil {
		return 0, false
	}
	return uint32(h.Session), true
}

// Hello is the client's opening message.
type Hello struct {
	Nonce [NonceLen]byte
	User  string
}

// AppendHello writes a HELLO body.
func AppendHello(b []byte, h Hello) []byte {
	b = append(b, h.Nonce[:]...)
	// The username is length-prefixed with one octet, so it is capped at 255 --
	// enforced by the caller, since silently truncating an identity would be a
	// nasty way to fail.
	b = append(b, byte(len(h.User)))
	return append(b, h.User...)
}

// ParseHello reads a HELLO body.
func ParseHello(b []byte) (Hello, error) {
	var h Hello
	if len(b) < NonceLen+1 {
		return h, ErrShort
	}
	copy(h.Nonce[:], b[:NonceLen])
	userLen := int(b[NonceLen])
	rest := b[NonceLen+1:]
	if len(rest) < userLen {
		return h, ErrMalformed
	}
	h.User = string(rest[:userLen])
	return h, nil
}

// AppendNonce writes a bare nonce body (CHALLENGE) or proof body (AUTH); both
// are a single fixed-width field.
func AppendNonce(b []byte, n []byte) []byte { return append(b, n...) }

// ParseFixed reads a fixed-width body of exactly n octets.
func ParseFixed(b []byte, n int) ([]byte, error) {
	if len(b) < n {
		return nil, ErrShort
	}
	return b[:n], nil
}

// Welcome is the server's acceptance, and becomes the caller's client.Result.
type Welcome struct {
	AssignedIP netip.Addr
	Netmask    netip.Addr
	Gateway    netip.Addr
	MTU        uint16
	DNS        []netip.Addr
}

// AppendWelcome writes a WELCOME body.
func AppendWelcome(b []byte, w Welcome) []byte {
	b = appendV4(b, w.AssignedIP)
	b = appendV4(b, w.Netmask)
	b = appendV4(b, w.Gateway)
	b = binary.BigEndian.AppendUint16(b, w.MTU)
	// The DNS count is one octet; more than 255 resolvers is not a real
	// configuration, and the cap keeps the parser's bound obvious.
	n := min(len(w.DNS), 255)
	b = append(b, byte(n))
	for _, d := range w.DNS[:n] {
		b = appendV4(b, d)
	}
	return b
}

// ParseWelcome reads a WELCOME body.
func ParseWelcome(b []byte) (Welcome, error) {
	var w Welcome
	const fixed = 4 + 4 + 4 + 2 + 1
	if len(b) < fixed {
		return w, ErrShort
	}
	w.AssignedIP = v4At(b[0:4])
	w.Netmask = v4At(b[4:8])
	w.Gateway = v4At(b[8:12])
	w.MTU = binary.BigEndian.Uint16(b[12:14])

	count := int(b[14])
	rest := b[fixed:]
	if len(rest) < count*4 {
		return w, ErrMalformed
	}
	for i := range count {
		w.DNS = append(w.DNS, v4At(rest[i*4:i*4+4]))
	}
	return w, nil
}

// AppendReject writes a REJECT body.
func AppendReject(b []byte, reason string) []byte {
	if len(reason) > 255 {
		reason = reason[:255]
	}
	b = append(b, byte(len(reason)))
	return append(b, reason...)
}

// The REJECT reasons the server sends, as constants both roles share.
//
// They are constants because the REJECT body is prose and nothing else: the
// wire format carries a length-prefixed string with no code beside it (SPEC.md,
// message 0x05). A client that wants to tell "your password is wrong" from
// "come back later" therefore has to match the text, and the only thing that
// keeps that from being a guess is both roles reading the same constant.
//
// Were TOY a protocol anyone deployed, this would be a defect worth fixing on
// the wire -- a numeric code beside the prose, the way every protocol in this
// tree that got it right does. It is left as it is, named, because TOY exists to
// be read: the shape of the mistake is more useful here than its absence.
const (
	RejectUnknownUser = "unknown user"
	RejectAuthFailed  = "authentication failed"
	RejectBusy        = "server busy"
	RejectNoSession   = "no session available"
	RejectPoolFull    = "address pool exhausted"
)

// RejectIsCredential reports whether a REJECT reason means the credentials were
// refused, as opposed to the server being unable to take the session right now.
// The difference decides whether retrying is useless (and, against a server that
// counts failures, harmful) or is exactly the right thing to do.
func RejectIsCredential(reason string) bool {
	return reason == RejectUnknownUser || reason == RejectAuthFailed
}

// ParseReject reads a REJECT body.
func ParseReject(b []byte) (string, error) {
	if len(b) < 1 {
		return "", ErrShort
	}
	n := int(b[0])
	if len(b[1:]) < n {
		return "", ErrMalformed
	}
	return string(b[1 : 1+n]), nil
}

func appendV4(b []byte, a netip.Addr) []byte {
	v4 := a.As4()
	return append(b, v4[:]...)
}

func v4At(b []byte) netip.Addr { return netip.AddrFrom4([4]byte(b)) }

// AddrToNetIP converts to the net.IP the client.Result contract uses.
func AddrToNetIP(a netip.Addr) net.IP {
	if !a.IsValid() {
		return nil
	}
	return net.IP(a.AsSlice())
}
