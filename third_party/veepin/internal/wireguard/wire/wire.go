// Package wire is the WireGuard message codec: the four message types, their
// fixed layouts, and the demux extractor the data-plane pump needs.
//
// It is deliberately free of crypto and state. Building a handshake initiation
// means filling a Message's fields with values the noise package computed, and
// parsing one means the reverse — so the wire format can be tested against
// fixtures without a handshake, and the handshake can be tested without a socket.
//
// Layouts are from the WireGuard protocol paper §5.4. Every field is
// little-endian, unlike IKEv2's network byte order; that alone is a common
// source of bugs, so the encoders and decoders here are the only place that
// touches raw offsets.
package wire

import (
	"encoding/binary"
	"errors"
	"time"
)

// Message types (protocol paper §5.4).
const (
	TypeHandshakeInitiation = 1
	TypeHandshakeResponse   = 2
	TypeCookieReply         = 3
	TypeTransportData       = 4
)

// Fixed message sizes in octets. WireGuard has no length fields: every handshake
// message is a fixed size, and anything else is malformed.
const (
	SizeHandshakeInitiation = 148
	SizeHandshakeResponse   = 92
	SizeCookieReply         = 64
	// MinTransportData is the header (16) plus the AEAD tag (16) of an empty
	// packet — what a keepalive weighs.
	MinTransportData = 32
)

// Field sizes.
const (
	KeySize      = 32 // Curve25519 public/private, and ChaCha20-Poly1305 keys
	TagSize      = 16 // Poly1305 authentication tag
	MACSize      = 16 // mac1 / mac2, keyed BLAKE2s truncated to 128 bits
	TimestampLen = 12 // TAI64N
	CookieSize   = 16
	NonceSize    = 24 // XChaCha20-Poly1305 nonce, cookie replies only
)

var (
	// ErrMalformed reports a packet that is not a valid WireGuard message: wrong
	// length, unknown type, or reserved bytes that are not zero. Inbound packets
	// are attacker-controlled, so this is a static error rather than a formatted
	// one — a flood of junk must not allocate.
	ErrMalformed = errors.New("wire: malformed message")
	// ErrShort reports a buffer too small to hold the message being encoded.
	ErrShort = errors.New("wire: buffer too short")
)

// Type reports a packet's message type, or false if the packet cannot carry one.
// The three reserved octets following the type must be zero (protocol paper
// §5.4); a peer that sets them is not speaking this protocol.
func Type(pkt []byte) (uint8, bool) {
	if len(pkt) < 4 {
		return 0, false
	}
	if pkt[1]|pkt[2]|pkt[3] != 0 {
		return 0, false
	}
	return pkt[0], true
}

// Demux extracts the receiver index a transport-data packet is addressed to, for
// dataplane.Demux.
//
// WireGuard puts it at offset 4, and only on type-4 messages: handshake and
// cookie packets carry a sender index there instead, and belong to the handshake
// state machine rather than to an established tunnel. This is exactly why the
// pump's demux is pluggable — ESP's SPI sits at offset 0 on every packet, so no
// fixed rule serves both.
func Demux(pkt []byte) (uint32, bool) {
	if len(pkt) < MinTransportData {
		return 0, false
	}
	t, ok := Type(pkt)
	if !ok || t != TypeTransportData {
		return 0, false
	}
	return binary.LittleEndian.Uint32(pkt[4:8]), true
}

// HandshakeInitiation is message type 1 (protocol paper §5.4.2).
//
//	0      type(1) reserved(3)
//	4      sender index (4)
//	8      unencrypted ephemeral (32)
//	40     encrypted static (32+16)
//	88     encrypted timestamp (12+16)
//	116    mac1 (16)
//	132    mac2 (16)
type HandshakeInitiation struct {
	Sender    uint32
	Ephemeral [KeySize]byte
	Static    [KeySize + TagSize]byte
	Timestamp [TimestampLen + TagSize]byte
	MAC1      [MACSize]byte
	MAC2      [MACSize]byte
}

// Offsets within a handshake initiation. mac1 covers everything before it, and
// mac2 everything before *it*, so the MAC boundaries are part of the format.
const (
	initMAC1Offset = 116
	initMAC2Offset = 132
)

// Marshal writes the initiation into dst, which must be at least
// SizeHandshakeInitiation octets, and returns the message slice.
func (m *HandshakeInitiation) Marshal(dst []byte) ([]byte, error) {
	if len(dst) < SizeHandshakeInitiation {
		return nil, ErrShort
	}
	b := dst[:SizeHandshakeInitiation]
	clear(b[:4])
	b[0] = TypeHandshakeInitiation
	binary.LittleEndian.PutUint32(b[4:8], m.Sender)
	copy(b[8:40], m.Ephemeral[:])
	copy(b[40:88], m.Static[:])
	copy(b[88:116], m.Timestamp[:])
	copy(b[initMAC1Offset:initMAC2Offset], m.MAC1[:])
	copy(b[initMAC2Offset:SizeHandshakeInitiation], m.MAC2[:])
	return b, nil
}

// ParseHandshakeInitiation decodes message type 1.
func ParseHandshakeInitiation(pkt []byte) (*HandshakeInitiation, error) {
	if len(pkt) != SizeHandshakeInitiation {
		return nil, ErrMalformed
	}
	if t, ok := Type(pkt); !ok || t != TypeHandshakeInitiation {
		return nil, ErrMalformed
	}
	m := &HandshakeInitiation{Sender: binary.LittleEndian.Uint32(pkt[4:8])}
	copy(m.Ephemeral[:], pkt[8:40])
	copy(m.Static[:], pkt[40:88])
	copy(m.Timestamp[:], pkt[88:116])
	copy(m.MAC1[:], pkt[initMAC1Offset:initMAC2Offset])
	copy(m.MAC2[:], pkt[initMAC2Offset:])
	return m, nil
}

// MACRegions returns the byte ranges mac1 and mac2 authenticate: everything
// preceding each. Callers compute the MACs over msg[:mac1] and msg[:mac2].
func MACRegions(msg []byte) (mac1Over, mac2Over []byte, ok bool) {
	switch {
	case len(msg) == SizeHandshakeInitiation:
		return msg[:initMAC1Offset], msg[:initMAC2Offset], true
	case len(msg) == SizeHandshakeResponse:
		return msg[:respMAC1Offset], msg[:respMAC2Offset], true
	}
	return nil, nil, false
}

// HandshakeResponse is message type 2 (protocol paper §5.4.3).
//
//	0      type(1) reserved(3)
//	4      sender index (4)
//	8      receiver index (4)
//	12     unencrypted ephemeral (32)
//	44     encrypted nothing (0+16)
//	60     mac1 (16)
//	76     mac2 (16)
type HandshakeResponse struct {
	Sender    uint32
	Receiver  uint32
	Ephemeral [KeySize]byte
	Empty     [TagSize]byte
	MAC1      [MACSize]byte
	MAC2      [MACSize]byte
}

const (
	respMAC1Offset = 60
	respMAC2Offset = 76
)

// Marshal writes the response into dst.
func (m *HandshakeResponse) Marshal(dst []byte) ([]byte, error) {
	if len(dst) < SizeHandshakeResponse {
		return nil, ErrShort
	}
	b := dst[:SizeHandshakeResponse]
	clear(b[:4])
	b[0] = TypeHandshakeResponse
	binary.LittleEndian.PutUint32(b[4:8], m.Sender)
	binary.LittleEndian.PutUint32(b[8:12], m.Receiver)
	copy(b[12:44], m.Ephemeral[:])
	copy(b[44:60], m.Empty[:])
	copy(b[respMAC1Offset:respMAC2Offset], m.MAC1[:])
	copy(b[respMAC2Offset:SizeHandshakeResponse], m.MAC2[:])
	return b, nil
}

// ParseHandshakeResponse decodes message type 2.
func ParseHandshakeResponse(pkt []byte) (*HandshakeResponse, error) {
	if len(pkt) != SizeHandshakeResponse {
		return nil, ErrMalformed
	}
	if t, ok := Type(pkt); !ok || t != TypeHandshakeResponse {
		return nil, ErrMalformed
	}
	m := &HandshakeResponse{
		Sender:   binary.LittleEndian.Uint32(pkt[4:8]),
		Receiver: binary.LittleEndian.Uint32(pkt[8:12]),
	}
	copy(m.Ephemeral[:], pkt[12:44])
	copy(m.Empty[:], pkt[44:60])
	copy(m.MAC1[:], pkt[respMAC1Offset:respMAC2Offset])
	copy(m.MAC2[:], pkt[respMAC2Offset:])
	return m, nil
}

// CookieReply is message type 3 (protocol paper §5.4.7), sent under load instead
// of a handshake response.
//
//	0      type(1) reserved(3)
//	4      receiver index (4)
//	8      nonce (24)
//	32     encrypted cookie (16+16)
type CookieReply struct {
	Receiver uint32
	Nonce    [NonceSize]byte
	Cookie   [CookieSize + TagSize]byte
}

// Marshal writes the cookie reply into dst, which must hold SizeCookieReply
// octets, and returns the message slice.
func (m *CookieReply) Marshal(dst []byte) ([]byte, error) {
	if len(dst) < SizeCookieReply {
		return nil, ErrShort
	}
	b := dst[:SizeCookieReply]
	clear(b[:4])
	b[0] = TypeCookieReply
	binary.LittleEndian.PutUint32(b[4:8], m.Receiver)
	copy(b[8:32], m.Nonce[:])
	copy(b[32:64], m.Cookie[:])
	return b, nil
}

// ParseCookieReply decodes message type 3.
func ParseCookieReply(pkt []byte) (*CookieReply, error) {
	if len(pkt) != SizeCookieReply {
		return nil, ErrMalformed
	}
	if t, ok := Type(pkt); !ok || t != TypeCookieReply {
		return nil, ErrMalformed
	}
	m := &CookieReply{Receiver: binary.LittleEndian.Uint32(pkt[4:8])}
	copy(m.Nonce[:], pkt[8:32])
	copy(m.Cookie[:], pkt[32:64])
	return m, nil
}

// TransportHeaderLen is type(1)+reserved(3)+receiver(4)+counter(8).
const TransportHeaderLen = 16

// TagLen is the ChaCha20-Poly1305 authentication tag appended to the ciphertext.
const TagLen = 16

// Overhead is what WireGuard adds to an inner packet on the wire: the transport
// header and the AEAD tag. It does not include the padding WireGuard applies to
// round a plaintext up to a multiple of 16 — that padding is why the protocol's
// conventional MTU leaves a little more slack than this sum alone accounts for.
const Overhead = TransportHeaderLen + TagLen

// PutTransportHeader writes a type-4 header into dst, which must be at least
// TransportHeaderLen octets. The packet body (the AEAD output) follows.
func PutTransportHeader(dst []byte, receiver uint32, counter uint64) error {
	if len(dst) < TransportHeaderLen {
		return ErrShort
	}
	clear(dst[:4])
	dst[0] = TypeTransportData
	binary.LittleEndian.PutUint32(dst[4:8], receiver)
	binary.LittleEndian.PutUint64(dst[8:16], counter)
	return nil
}

// TransportCounter reads the nonce counter from a type-4 packet. The caller has
// already demuxed on the receiver index.
func TransportCounter(pkt []byte) (uint64, bool) {
	if len(pkt) < TransportHeaderLen {
		return 0, false
	}
	return binary.LittleEndian.Uint64(pkt[8:16]), true
}

// tai64nBase is the TAI64 label for 1970-01-01 00:00:00 UTC: 2^62 seconds.
const tai64nBase = 1 << 62

// Timestamp returns t as TAI64N, the 12-octet format WireGuard uses to reject
// replayed handshake initiations (protocol paper §5.1).
//
// It is TAI, not UTC, so a strict encoder would add leap seconds. WireGuard's
// own implementations do not, and correctness here depends only on the value
// increasing monotonically between handshakes from the same peer, which a
// constant offset preserves. Adding leap seconds would in fact break interop.
func Timestamp(t time.Time) [TimestampLen]byte {
	var out [TimestampLen]byte
	binary.BigEndian.PutUint64(out[0:8], uint64(tai64nBase+t.Unix()))
	binary.BigEndian.PutUint32(out[8:12], uint32(t.Nanosecond()))
	return out
}

// After reports whether TAI64N timestamp a is strictly later than b. Both are
// big-endian, so a byte-wise comparison is a numeric one — which is the point of
// the format.
func After(a, b [TimestampLen]byte) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return false
}
