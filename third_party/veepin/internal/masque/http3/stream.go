package http3

// A request stream and its two lives.
//
// Before the tunnel is up it carries HTTP/3 HEADERS frames: the client's
// Extended CONNECT and the server's status response. After that it carries the
// capsule byte stream, which in HTTP/3 travels inside DATA frames (RFC 9297).
// RequestStream presents that second life as a plain io.ReadWriteCloser of
// capsule bytes: Write wraps a buffer in one DATA frame, and Read returns the
// concatenated payloads of incoming DATA frames. The capsule TLV parsing lives a
// layer up, in package masque, which reads and writes this as an ordinary
// stream and never sees a frame.

import (
	"fmt"

	"golang.org/x/net/quic"
)

// RequestStream is one HTTP/3 request: headers, then a capsule byte stream.
type RequestStream struct {
	qs      *quic.Stream
	readBuf []byte // capsule-stream bytes carried over from a partial DATA frame
	// hdrBuf is the DATA frame header scratch for Write. It lives here so that
	// framing a packet on the data path does not allocate: the stream is already
	// on the heap, so writing through this buffer costs nothing per call.
	hdrBuf []byte
}

// readHeaders reads the HEADERS frame at the head of the stream and decodes its
// QPACK field section. Frames before HEADERS that are not HEADERS are a protocol
// error on a request stream.
func (rs *RequestStream) readHeaders() ([]Field, error) {
	typ, payload, err := ReadFrame(rs.qs)
	if err != nil {
		return nil, err
	}
	if typ != FrameHeaders {
		return nil, fmt.Errorf("http3: first request frame is %#x, not HEADERS", typ)
	}
	return DecodeFieldSection(payload)
}

// WriteResponse writes the server's response HEADERS frame. It is called once,
// before any capsules, with at least a :status field.
func (rs *RequestStream) WriteResponse(fields []Field) error {
	if err := WriteFrame(rs.qs, FrameHeaders, EncodeFieldSection(fields)); err != nil {
		return err
	}
	return rs.qs.Flush()
}

// ReadResponse reads the server's response HEADERS frame, for the client side.
func (rs *RequestStream) ReadResponse() ([]Field, error) {
	return rs.readHeaders()
}

// Write sends p as the payload of one DATA frame. The masque layer calls this
// with a whole capsule, so one capsule becomes one DATA frame — the peer is free
// to reframe, which is why Read does not assume that boundary holds.
func (rs *RequestStream) Write(p []byte) (int, error) {
	rs.hdrBuf = AppendVarint(rs.hdrBuf[:0], FrameData)
	rs.hdrBuf = AppendVarint(rs.hdrBuf, uint64(len(p)))
	if _, err := rs.qs.Write(rs.hdrBuf); err != nil {
		return 0, err
	}
	if _, err := rs.qs.Write(p); err != nil {
		return 0, err
	}
	if err := rs.qs.Flush(); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Read fills p from the capsule byte stream, reading DATA frames as needed.
// Non-DATA frames arriving mid-stream are skipped, as RFC 9114 §9 requires of
// unexpected frames, rather than corrupting the capsule stream.
func (rs *RequestStream) Read(p []byte) (int, error) {
	for len(rs.readBuf) == 0 {
		typ, payload, err := ReadFrame(rs.qs)
		if err != nil {
			return 0, err
		}
		if typ == FrameData {
			rs.readBuf = payload
		}
		// Any other frame type between DATA frames is ignored.
	}
	n := copy(p, rs.readBuf)
	rs.readBuf = rs.readBuf[n:]
	return n, nil
}

// Close closes the underlying stream in both directions.
func (rs *RequestStream) Close() error { return rs.qs.Close() }

// CloseWrite half-closes the send side, signalling no more capsules. It fails
// only for a stream that has no send side, which a request stream always has.
func (rs *RequestStream) CloseWrite() error { return rs.qs.CloseWrite() }
