// Package fortinet implements the FortiOS SSL VPN protocol: the HTTPS
// authentication and configuration exchange, and the PPP-over-TLS data tunnel.
//
// It is transport-light on purpose. The heavy lifting is reused: PPP link setup
// (LCP/IPCP) is internal/ppp, and the carrier is an ordinary TLS connection. What
// is specific to Fortinet is small — the way each PPP frame is framed on the wire,
// the login form and its session cookie, and the XML that carries the assigned
// address and routes.
package fortinet

import (
	"encoding/binary"
	"errors"
	"io"
)

// The data channel wraps every PPP frame in a 6-octet header (openconnect's
// PPP_ENCAP_FORTINET):
//
//	0      2        4        6
//	+------+--------+--------+------------------+
//	|len BE| 0x5050 |plen BE |  bare PPP frame  |
//	+------+--------+--------+------------------+
//
// len is the whole record (plen + 6); plen is the PPP frame alone. The redundant
// length is Fortinet's, not ours to question — both fields are checked on parse,
// and a record whose two lengths disagree is rejected rather than guessed at.
const (
	frameHeaderLen = 6
	// frameMagic is the constant 16-bit value at octets 2..3 of every record.
	frameMagic = 0x5050
	// maxFramePayload bounds a single PPP frame this code will buffer. A PPP
	// control or IP frame is well under this; the ceiling stops a hostile length
	// from forcing an unbounded allocation.
	maxFramePayload = 1 << 16
)

var (
	// ErrShortFrame reports a record too short to hold the 6-octet header.
	ErrShortFrame = errors.New("fortinet: record shorter than its header")
	// ErrBadMagic reports the 0x5050 constant being wrong — usually a desynced
	// stream rather than a short read.
	ErrBadMagic = errors.New("fortinet: record magic is not 0x5050")
	// ErrLengthMismatch reports the outer and inner length fields disagreeing.
	ErrLengthMismatch = errors.New("fortinet: record length fields disagree")
	// ErrFrameTooLarge reports a PPP frame larger than the buffer ceiling.
	ErrFrameTooLarge = errors.New("fortinet: PPP frame exceeds the maximum")
)

// EncodeFrame wraps a bare PPP frame in the Fortinet 6-octet header.
func EncodeFrame(ppp []byte) []byte {
	out := make([]byte, frameHeaderLen+len(ppp))
	binary.BigEndian.PutUint16(out[0:2], uint16(len(ppp)+frameHeaderLen))
	binary.BigEndian.PutUint16(out[2:4], frameMagic)
	binary.BigEndian.PutUint16(out[4:6], uint16(len(ppp)))
	copy(out[frameHeaderLen:], ppp)
	return out
}

// ParseFrame reads the header at the front of buf and returns the PPP frame and
// the remaining bytes. It reports the header being incomplete separately from it
// being malformed: a caller streaming records needs to tell "read more" from
// "this peer is broken".
func ParseFrame(buf []byte) (ppp, rest []byte, err error) {
	if len(buf) < frameHeaderLen {
		return nil, buf, ErrShortFrame
	}
	total := binary.BigEndian.Uint16(buf[0:2])
	magic := binary.BigEndian.Uint16(buf[2:4])
	plen := binary.BigEndian.Uint16(buf[4:6])

	if magic != frameMagic {
		return nil, buf, ErrBadMagic
	}
	if int(total) != int(plen)+frameHeaderLen {
		return nil, buf, ErrLengthMismatch
	}
	if int(plen) > maxFramePayload {
		return nil, buf, ErrFrameTooLarge
	}
	if len(buf) < frameHeaderLen+int(plen) {
		// The header is valid but the payload has not all arrived yet.
		return nil, buf, ErrShortFrame
	}
	return buf[frameHeaderLen : frameHeaderLen+int(plen)], buf[frameHeaderLen+int(plen):], nil
}

// ReadFrame reads exactly one framed PPP record from r. It reads the 6-octet
// header first, then the payload its length announces, so it never consumes into
// the next record — which a stream transport requires.
func ReadFrame(r io.Reader) ([]byte, error) {
	var hdr [frameHeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	total := binary.BigEndian.Uint16(hdr[0:2])
	magic := binary.BigEndian.Uint16(hdr[2:4])
	plen := binary.BigEndian.Uint16(hdr[4:6])

	if magic != frameMagic {
		return nil, ErrBadMagic
	}
	if int(total) != int(plen)+frameHeaderLen {
		return nil, ErrLengthMismatch
	}
	if int(plen) > maxFramePayload {
		return nil, ErrFrameTooLarge
	}
	ppp := make([]byte, plen)
	if _, err := io.ReadFull(r, ppp); err != nil {
		return nil, err
	}
	return ppp, nil
}
