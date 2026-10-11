package ike

import (
	"encoding/binary"
	"errors"
	"io"
)

// TCP encapsulation of IKE and ESP (RFC 8229, updated by RFC 9329).
//
//	originator                              responder
//	    |------ "IKETCP" ---------------------->|   once, originator only
//	    |------ [len][0,0,0,0][IKE message] --->|
//	    |<----- [len][ESP packet] --------------|
//
// Three facts decide the codec, and two of them are easy to get wrong from
// memory:
//
//   - The stream prefix is the six ASCII octets "IKETCP", sent ONCE and by the
//     TCP ORIGINATOR ONLY. The responder never sends it, so a responder that
//     waits for one from its peer deadlocks, and one that sends its own
//     corrupts the first frame the originator reads.
//   - The 16-bit Length INCLUDES ITSELF. RFC 8229 section 3: "Length of the IKE
//     packet, including the Length field and non-ESP marker", and for ESP
//     "including the Length field". Treating it as the payload length alone is
//     an off-by-two that puts a stream two octets out of phase on the very
//     first message -- and silently, because the next read still returns bytes.
//   - Inside the stream, an IKE message carries the same 4-octet zero non-ESP
//     marker used on UDP 4500, and an ESP packet does not. That is the only
//     thing separating them, exactly as on the datagram transport.
const tcpStreamPrefix = "IKETCP"

// tcpLenSize is the framing length field: 2 octets, and it counts itself.
const tcpLenSize = 2

// maxTCPFrame bounds one frame. The length field is 16 bits, so this is its
// ceiling; it exists so a hostile peer cannot make us buffer more than the
// format allows.
const maxTCPFrame = 0xffff

var (
	errTCPFrameShort = errors.New("ike: TCP frame length below its own header")
	errTCPBadPrefix  = errors.New("ike: TCP stream did not begin with IKETCP")
	errTCPFrameEmpty = errors.New("ike: TCP frame carries no payload")
)

// appendTCPFrame appends one length-prefixed frame carrying payload.
//
// payload is the complete message as it appears on the wire: for IKE that
// INCLUDES the leading 4-octet non-ESP marker, because the length counts it.
func appendTCPFrame(dst, payload []byte) []byte {
	dst = binary.BigEndian.AppendUint16(dst, uint16(tcpLenSize+len(payload)))
	return append(dst, payload...)
}

// appendTCPIKE frames one IKE message, inserting the non-ESP marker the format
// requires so a reader can tell it from ESP.
func appendTCPIKE(dst, ike []byte) []byte {
	dst = binary.BigEndian.AppendUint16(dst, uint16(tcpLenSize+len(nonESPMarker)+len(ike)))
	dst = append(dst, nonESPMarker...)
	return append(dst, ike...)
}

// tcpFrameIsIKE reports whether a frame payload is an IKE message rather than
// an ESP packet, by the non-ESP marker. An ESP packet begins with a non-zero
// SPI, so four zero octets mean IKE.
func tcpFrameIsIKE(payload []byte) bool {
	return len(payload) >= 4 && payload[0] == 0 && payload[1] == 0 && payload[2] == 0 && payload[3] == 0
}

// tcpReader reassembles RFC 8229 frames from a byte stream.
//
// It keeps one buffer and slides within it rather than allocating per frame;
// Next returns a subslice of that buffer, valid until the following call. That
// is the same borrowed-buffer contract the datagram parsers use, and it is why
// the ESP path can stay allocation-free over TCP too.
type tcpReader struct {
	r   io.Reader
	buf []byte
	// start and end bound the unconsumed bytes within buf.
	start, end int
	// prefixSeen records that the peer's stream prefix has been consumed. Only
	// a responder expects one.
	prefixSeen bool
}

func newTCPReader(r io.Reader) *tcpReader {
	return &tcpReader{r: r, buf: make([]byte, 0, 4096)}
}

// expectPrefix consumes the six-octet stream prefix a TCP originator sends. A
// responder calls this once before reading frames; an originator never does,
// because its peer sends no prefix.
func (t *tcpReader) expectPrefix() error {
	if err := t.fill(len(tcpStreamPrefix)); err != nil {
		return err
	}
	if string(t.buf[t.start:t.start+len(tcpStreamPrefix)]) != tcpStreamPrefix {
		return errTCPBadPrefix
	}
	t.start += len(tcpStreamPrefix)
	t.prefixSeen = true
	return nil
}

// Next returns the next frame's payload -- the message with its non-ESP marker
// still attached for IKE, and the bare ESP packet otherwise. The returned slice
// is only valid until the next call.
func (t *tcpReader) Next() ([]byte, error) {
	if err := t.fill(tcpLenSize); err != nil {
		return nil, err
	}
	total := int(binary.BigEndian.Uint16(t.buf[t.start:]))
	if total < tcpLenSize {
		return nil, errTCPFrameShort
	}
	if total == tcpLenSize {
		// A frame whose only content is its own length. RFC 8229 has no such
		// message; accepting it would spin the reader forever on a zero-length
		// payload.
		return nil, errTCPFrameEmpty
	}
	if err := t.fill(total); err != nil {
		return nil, err
	}
	payload := t.buf[t.start+tcpLenSize : t.start+total]
	t.start += total
	return payload, nil
}

// fill ensures at least n unconsumed octets are buffered, reading more when
// needed and compacting when the window has drifted far enough right to be
// worth it.
func (t *tcpReader) fill(n int) error {
	if n > maxTCPFrame {
		return errTCPFrameShort
	}
	for t.end-t.start < n {
		// Compact before growing: a long-lived stream would otherwise walk the
		// buffer rightwards forever.
		if t.start > 0 && (t.end-t.start)+n > cap(t.buf)-t.start {
			copy(t.buf[:0:cap(t.buf)], t.buf[t.start:t.end])
			t.end -= t.start
			t.start = 0
		}
		if cap(t.buf) < t.end+n {
			grown := make([]byte, t.end, max(t.end+n, 2*cap(t.buf)+n))
			copy(grown, t.buf[:t.end])
			t.buf = grown
		}
		t.buf = t.buf[:cap(t.buf)]
		nr, err := t.r.Read(t.buf[t.end:])
		t.end += nr
		if err != nil {
			if nr > 0 && t.end-t.start >= n {
				continue
			}
			return err
		}
	}
	return nil
}
