package payload

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrTruncated is returned when a buffer is too short to hold the structure
// being decoded.
var ErrTruncated = errors.New("payload: buffer truncated")

// HeaderLen is the fixed size of the IKEv2 header (RFC 7296 section 3.1).
const HeaderLen = 28

// genericPayloadHeaderLen is the size of the generic payload header that
// precedes every payload body (RFC 7296 section 3.2).
const genericPayloadHeaderLen = 4

// Header is the fixed 28-octet IKEv2 message header.
type Header struct {
	InitiatorSPI uint64
	ResponderSPI uint64
	NextPayload  PayloadType
	Version      uint8 // major<<4 | minor; always 0x20 for IKEv2
	ExchangeType ExchangeType
	Flags        uint8
	MessageID    uint32
	Length       uint32 // total message length including header
}

// IsInitiator reports whether the original-initiator flag is set.
func (h *Header) IsInitiator() bool { return h.Flags&FlagInitiator != 0 }

// IsResponse reports whether the response flag is set.
func (h *Header) IsResponse() bool { return h.Flags&FlagResponse != 0 }

// Marshal appends the encoded header to dst and returns the extended slice.
func (h *Header) Marshal(dst []byte) []byte {
	var b [HeaderLen]byte
	binary.BigEndian.PutUint64(b[0:8], h.InitiatorSPI)
	binary.BigEndian.PutUint64(b[8:16], h.ResponderSPI)
	b[16] = byte(h.NextPayload)
	b[17] = h.Version
	b[18] = byte(h.ExchangeType)
	b[19] = h.Flags
	binary.BigEndian.PutUint32(b[20:24], h.MessageID)
	binary.BigEndian.PutUint32(b[24:28], h.Length)
	return append(dst, b[:]...)
}

// ParseHeader decodes the fixed header from the front of buf.
func ParseHeader(buf []byte) (Header, error) {
	if len(buf) < HeaderLen {
		return Header{}, ErrTruncated
	}
	h := Header{
		InitiatorSPI: binary.BigEndian.Uint64(buf[0:8]),
		ResponderSPI: binary.BigEndian.Uint64(buf[8:16]),
		NextPayload:  PayloadType(buf[16]),
		Version:      buf[17],
		ExchangeType: ExchangeType(buf[18]),
		Flags:        buf[19],
		MessageID:    binary.BigEndian.Uint32(buf[20:24]),
		Length:       binary.BigEndian.Uint32(buf[24:28]),
	}
	return h, nil
}

// RawPayload is a decoded generic payload: its type, critical bit and body.
// The body excludes the 4-octet generic payload header.
type RawPayload struct {
	Type     PayloadType
	Critical bool
	Body     []byte
}

// Message is a parsed IKEv2 message: the header plus an ordered list of the
// top-level (unencrypted) payloads. Encrypted contents live inside the SK
// payload and are parsed separately after decryption.
type Message struct {
	Header   Header
	Payloads []RawPayload
}

// FirstPayloadType returns the type of the first payload, or NoNextPayload.
func (m *Message) FirstPayloadType() PayloadType {
	if len(m.Payloads) == 0 {
		return NoNextPayload
	}
	return m.Payloads[0].Type
}

// Find returns the first payload of type t, or nil.
func (m *Message) Find(t PayloadType) *RawPayload {
	for i := range m.Payloads {
		if m.Payloads[i].Type == t {
			return &m.Payloads[i]
		}
	}
	return nil
}

// FindAll returns every payload of type t in order.
func (m *Message) FindAll(t PayloadType) []RawPayload {
	var out []RawPayload
	for i := range m.Payloads {
		if m.Payloads[i].Type == t {
			out = append(out, m.Payloads[i])
		}
	}
	return out
}

// ParseMessage decodes a complete IKEv2 message. It validates the header
// length field against the actual buffer and walks the payload chain.
func ParseMessage(buf []byte) (*Message, error) {
	h, err := ParseHeader(buf)
	if err != nil {
		return nil, err
	}
	if int(h.Length) != len(buf) {
		return nil, fmt.Errorf("payload: header length %d != buffer length %d", h.Length, len(buf))
	}
	payloads, err := parsePayloadChain(h.NextPayload, buf[HeaderLen:])
	if err != nil {
		return nil, err
	}
	return &Message{Header: h, Payloads: payloads}, nil
}

// parsePayloadChain walks a chain of generic payloads. Each generic header
// carries the *next* payload's type, so decoding threads that value along.
func parsePayloadChain(first PayloadType, buf []byte) ([]RawPayload, error) {
	var out []RawPayload
	next := first
	off := 0
	for next != NoNextPayload {
		if off+genericPayloadHeaderLen > len(buf) {
			return nil, ErrTruncated
		}
		thisType := next
		nextType := PayloadType(buf[off])
		critical := buf[off+1]&0x80 != 0
		length := int(binary.BigEndian.Uint16(buf[off+2 : off+4]))
		if length < genericPayloadHeaderLen || off+length > len(buf) {
			return nil, fmt.Errorf("payload: bad length %d for %s", length, thisType)
		}
		body := buf[off+genericPayloadHeaderLen : off+length]
		out = append(out, RawPayload{Type: thisType, Critical: critical, Body: body})
		off += length
		// The Encrypted (SK) payload — and its fragment form (SKF, RFC 7383) —
		// is always terminal in the unencrypted chain: its NextPayload names the
		// first *inner* payload, and its body is ciphertext rather than further
		// generic payloads. Stop here.
		if thisType == TypeSK || thisType == TypeSKF {
			break
		}
		next = nextType
	}
	return out, nil
}

// Builder assembles the payload chain of a message, back-patching each
// generic header's NextPayload field as payloads are appended.
type Builder struct {
	buf         []byte
	firstType   PayloadType
	haveFirst   bool
	lastNextOff int // offset of the NextPayload byte needing back-patch
	lastLenOff  int
}

// NewBuilder returns an empty payload-chain builder.
func NewBuilder() *Builder {
	return &Builder{lastNextOff: -1}
}

// Add appends one payload of type t with the given body, fixing up the
// previous payload's NextPayload link.
func (b *Builder) Add(t PayloadType, critical bool, body []byte) {
	if !b.haveFirst {
		b.firstType = t
		b.haveFirst = true
	} else {
		b.buf[b.lastNextOff] = byte(t)
	}
	start := len(b.buf)
	crit := byte(0)
	if critical {
		crit = 0x80
	}
	// generic header: NextPayload(0, patched later), Critical|Reserved, Length
	total := genericPayloadHeaderLen + len(body)
	var hdr [genericPayloadHeaderLen]byte
	hdr[0] = byte(NoNextPayload)
	hdr[1] = crit
	binary.BigEndian.PutUint16(hdr[2:4], uint16(total))
	b.buf = append(b.buf, hdr[:]...)
	b.buf = append(b.buf, body...)
	b.lastNextOff = start // the NextPayload byte we may patch on the next Add
	b.lastLenOff = start + 2
}

// FirstType returns the type of the first payload added, for the header.
func (b *Builder) FirstType() PayloadType {
	if !b.haveFirst {
		return NoNextPayload
	}
	return b.firstType
}

// Bytes returns the assembled payload chain (without the IKE header).
func (b *Builder) Bytes() []byte { return b.buf }
