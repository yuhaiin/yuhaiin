// Package http3 is the sliver of HTTP/3 that MASQUE needs, built on the public
// golang.org/x/net/quic package.
//
// It is deliberately not a general HTTP/3 stack. x/net ships one, but only for
// net/http's private use — its public package exports nothing, and its internals
// have no Extended CONNECT, no HTTP Datagrams and no Capsule Protocol, which are
// the three things a MASQUE tunnel is made of. So this package implements just
// enough: variable-length integers, the two frame types a CONNECT exchange
// touches, the control-stream SETTINGS handshake, and a QPACK encoder/decoder
// restricted to a zero-capacity dynamic table. Everything here is sized to make
// one Extended CONNECT request work and to interoperate with a real HTTP/3
// proxy, not to serve web pages.
package http3

import (
	"errors"
	"io"
)

// ErrVarintOverflow reports a varint that does not fit the buffer, or a value
// too large to encode. RFC 9000 §16 caps a varint at 2^62-1.
var ErrVarintOverflow = errors.New("http3: varint truncated or out of range")

// maxVarint is the largest value a QUIC varint can hold: 2^62 - 1.
const maxVarint = (1 << 62) - 1

// AppendVarint encodes v as a QUIC variable-length integer (RFC 9000 §16) and
// appends it to dst. The two most-significant bits of the first byte select the
// length — 1, 2, 4 or 8 octets — so the encoder picks the shortest that fits.
func AppendVarint(dst []byte, v uint64) []byte {
	switch {
	case v <= 63:
		return append(dst, byte(v))
	case v <= 16383:
		return append(dst, byte(v>>8)|0x40, byte(v))
	case v <= 1073741823:
		return append(dst, byte(v>>24)|0x80, byte(v>>16), byte(v>>8), byte(v))
	default:
		return append(dst,
			byte(v>>56)|0xc0, byte(v>>48), byte(v>>40), byte(v>>32),
			byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
}

// VarintLen reports how many octets AppendVarint would use for v. It lets a
// caller size a length prefix whose value includes its own encoded length,
// which the capsule and frame headers do not need but the QPACK prefix math
// benefits from having available.
func VarintLen(v uint64) int {
	switch {
	case v <= 63:
		return 1
	case v <= 16383:
		return 2
	case v <= 1073741823:
		return 4
	default:
		return 8
	}
}

// ConsumeVarint decodes one varint from the front of b, returning the value and
// the remaining bytes. A buffer too short for the length the first byte
// announces is an overflow, not a partial read: callers here always hold a
// whole frame or capsule value before decoding.
func ConsumeVarint(b []byte) (v uint64, rest []byte, err error) {
	if len(b) == 0 {
		return 0, b, ErrVarintOverflow
	}
	// The prefix length is 2^(top two bits): 1, 2, 4 or 8.
	n := 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, b, ErrVarintOverflow
	}
	v = uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, b[n:], nil
}

// ReadVarint decodes one varint from r, reading only as many octets as its
// first byte requires. It is used on the QUIC streams, where a frame header is
// consumed before its payload length is known and there is nothing to
// pre-buffer against.
func ReadVarint(r io.Reader) (uint64, error) {
	// One buffer for both reads: it escapes to the heap either way (io.ReadFull
	// takes an interface), so sizing it for the longest varint costs a single
	// small allocation rather than two.
	var buf [8]byte
	if _, err := io.ReadFull(r, buf[:1]); err != nil {
		return 0, err
	}
	n := 1 << (buf[0] >> 6)
	v := uint64(buf[0] & 0x3f)
	if n == 1 {
		return v, nil
	}
	if _, err := io.ReadFull(r, buf[1:n]); err != nil {
		return 0, err
	}
	for _, c := range buf[1:n] {
		v = v<<8 | uint64(c)
	}
	return v, nil
}
