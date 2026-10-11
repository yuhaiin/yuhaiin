package http3

// HTTP/3 frames (RFC 9114 §7.2), narrowed to the three a CONNECT tunnel uses.
//
// A frame is a varint type, a varint length, and that many payload octets. Only
// SETTINGS, HEADERS and DATA are handled: SETTINGS is exchanged once on each
// side's control stream, HEADERS carries the QPACK-encoded CONNECT request and
// its response, and DATA frames carry the capsule stream once the tunnel is up
// (RFC 9297: in HTTP/3 the capsule bytes are the payload of DATA frames).
// Frame types this code does not send — PUSH_PROMISE, GOAWAY and the rest — are
// skipped on receipt rather than rejected, as RFC 9114 §9 requires of unknown
// and unexpected frames.

import (
	"errors"
	"fmt"
	"io"
)

// Frame type codes (RFC 9114 §7.2 and §11.2.1).
const (
	FrameData     = 0x00
	FrameHeaders  = 0x01
	FrameSettings = 0x04
)

// maxFramePayload bounds a single frame this code will buffer. A CONNECT
// request's HEADERS and a SETTINGS frame are tiny; a DATA frame carries one
// capsule, which for a VPN is one inner packet. 64 KiB is well above any of
// these and stops a hostile length varint from forcing an unbounded allocation.
const maxFramePayload = 1 << 16

// ErrFrameTooLarge reports a frame whose announced length exceeds what this code
// will buffer, which is treated as a peer error rather than an allocation.
var ErrFrameTooLarge = errors.New("http3: frame payload exceeds the maximum")

// WriteFrame writes one frame: type, length, payload.
func WriteFrame(w io.Writer, typ uint64, payload []byte) error {
	hdr := AppendVarint(nil, typ)
	hdr = AppendVarint(hdr, uint64(len(payload)))
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := w.Write(payload)
	return err
}

// ReadFrame reads one frame's type and payload. A frame larger than
// maxFramePayload is refused before its length is allocated.
func ReadFrame(r io.Reader) (typ uint64, payload []byte, err error) {
	typ, err = ReadVarint(r)
	if err != nil {
		return 0, nil, err
	}
	length, err := ReadVarint(r)
	if err != nil {
		return 0, nil, err
	}
	if length > maxFramePayload {
		return 0, nil, fmt.Errorf("%w: %d octets", ErrFrameTooLarge, length)
	}
	payload = make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return typ, payload, nil
}
