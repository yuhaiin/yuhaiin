package l2tpv3

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

// L2TPv3 data packet over UDP (RFC 3931 section 4.1.2.1):
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|T|x|x|x|x|x|x|x|x|x|x|x|  Ver  |             Res               |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                           Session ID                          |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                  Cookie (0, 4 or 8 octets)                    |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|      Default L2-Specific Sublayer (0 or 4 octets)             |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                       Ethernet frame                          |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Note the first word's layout: the T bit is the MSB and the version is the
// LOW four bits, with eleven unassigned bits between them. The whole word is
// not the version -- comparing it against 3 happens to work against Linux,
// which zeroes the x bits, and rejects any peer that does not.

const (
	// l2tpHeaderLen is the fixed portion: flags+ver (2) + reserved (2) +
	// session ID (4).
	l2tpHeaderLen = 8
	// sublayerLen is the Default L2-Specific Sublayer when the session was
	// configured with one.
	sublayerLen = 4
	// l2tpVer is the value of the 4-bit version field for L2TPv3.
	l2tpVer = 3
	// verMask selects the version field out of the first 16-bit word.
	verMask = 0x000f
	// tBitMask selects the T bit: 1 for a control message, 0 for data.
	tBitMask = 0x8000
)

// Drop-path errors are pre-built sentinels. A peer that floods malformed
// packets should cost no allocations to reject.
var (
	ErrShort     = errors.New("l2tpv3: data packet shorter than its header")
	ErrVersion   = errors.New("l2tpv3: not an L2TPv3 packet")
	ErrControl   = errors.New("l2tpv3: control message (T=1) on the data path")
	ErrCookie    = errors.New("l2tpv3: cookie mismatch")
	ErrCookieLen = errors.New("l2tpv3: cookie must be 0, 4 or 8 octets")
)

// ValidCookieLen reports whether n is a length RFC 3931 permits for a cookie.
func ValidCookieLen(n int) bool { return n == 0 || n == 4 || n == 8 }

// DataHeaderLen returns the header overhead for a data packet given the cookie
// length and whether the session carries a sublayer.
func DataHeaderLen(cookieLen int, sublayer bool) int {
	n := l2tpHeaderLen + cookieLen
	if sublayer {
		n += sublayerLen
	}
	return n
}

// EncodeData writes an L2TPv3 data packet into dst and returns it. dst is
// reused when it has the capacity and reallocated when it does not, so a
// caller that keeps one buffer per sender goroutine encodes without allocating.
//
// The Ethernet frame is copied. There is no way to avoid that here: the header
// precedes the frame on the wire and the frame arrives in a TAP read buffer, so
// scatter-gather would have to reach the socket, not this function.
//
// cookie is the cookie the PEER expects on its receive side -- see
// SessionConfig.RemoteCookie for why that is the one that goes out.
func EncodeData(dst []byte, sessionID uint32, cookie []byte, sublayer bool, frame []byte) []byte {
	hdrLen := DataHeaderLen(len(cookie), sublayer)
	total := hdrLen + len(frame)

	if cap(dst) < total {
		dst = make([]byte, total)
	}
	dst = dst[:total]

	// T=0 (data message), every x bit zero, Ver=3.
	binary.BigEndian.PutUint16(dst[0:], l2tpVer)
	binary.BigEndian.PutUint16(dst[2:], 0) // Res
	binary.BigEndian.PutUint32(dst[4:], sessionID)
	copy(dst[l2tpHeaderLen:], cookie)

	if sublayer {
		// The Default L2-Specific Sublayer with sequencing off is four zero
		// octets (S=0, and the sequence number unused). They must be written
		// rather than assumed: on a reused dst they would otherwise be whatever
		// the previous packet left behind.
		subOff := l2tpHeaderLen + len(cookie)
		clear(dst[subOff : subOff+sublayerLen])
	}

	copy(dst[hdrLen:], frame)
	return dst
}

// DecodeData parses one L2TPv3 data packet and returns the inner Ethernet
// frame as a subslice of pkt. It allocates nothing, on the accept path or the
// drop path.
//
// cookie is what THIS end chose for its own receive side; a packet carrying
// anything else is rejected. That check is the cookie's entire purpose --
// RFC 3931 section 4.1.2.1 calls it a guard against mis-directed packets and
// blind insertion attacks -- so decoding without it makes the field decorative.
// It is compared in constant time because it is a secret an off-path attacker
// is trying to guess.
func DecodeData(pkt []byte, cookie []byte, sublayer bool) (sessionID uint32, frame []byte, err error) {
	hdrLen := DataHeaderLen(len(cookie), sublayer)
	if len(pkt) < hdrLen {
		return 0, nil, ErrShort
	}

	word := binary.BigEndian.Uint16(pkt[0:])
	if word&tBitMask != 0 {
		return 0, nil, ErrControl
	}
	if word&verMask != l2tpVer {
		return 0, nil, ErrVersion
	}

	if len(cookie) > 0 {
		got := pkt[l2tpHeaderLen : l2tpHeaderLen+len(cookie)]
		if subtle.ConstantTimeCompare(got, cookie) != 1 {
			return 0, nil, ErrCookie
		}
	}

	// The sublayer is skipped, not parsed. With sequencing off -- the only mode
	// a static pseudowire uses, and what Linux emits -- it carries no
	// information, and treating a zero sublayer as absent would mis-frame every
	// packet the kernel sends. Presence is a session property, never inferred.

	return binary.BigEndian.Uint32(pkt[4:]), pkt[hdrLen:], nil
}
