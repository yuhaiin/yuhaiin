package http3

// QPACK (RFC 9204), restricted to what a MASQUE CONNECT exchange needs.
//
// The full protocol has a dynamic table shared across a connection and kept in
// sync by instructions on dedicated encoder/decoder streams. None of that is
// needed here: a CONNECT request and its response are a handful of pseudo-header
// fields sent once, so this encoder advertises a zero-capacity dynamic table and
// emits only two representations — an Indexed Field Line into the static table,
// and a Literal Field Line. With no dynamic entries there are never any
// encoder-stream instructions to send, which removes the one genuinely stateful
// part of QPACK.
//
// The decoder is the mirror: it reads the mandatory field-section prefix
// (Required Insert Count and Base, both zero here), then each field line as
// either a static-table reference or a literal, and it accepts Huffman-coded
// literals because a compliant peer is free to send them even when we do not.

import (
	"errors"
	"fmt"
)

// ErrQPACK reports a header block this decoder cannot parse. A dynamic-table
// reference is included: it is legal QPACK, but this decoder advertised zero
// capacity, so receiving one means the peer ignored that and the block cannot be
// decoded without state we deliberately do not keep.
var ErrQPACK = errors.New("http3: QPACK block is malformed or uses the dynamic table")

// Field is one header field. HTTP/3 pseudo-headers (":method", ":status", ...)
// are ordinary fields whose name begins with a colon.
type Field struct {
	Name  string
	Value string
}

// statusStatic maps a :status value to its static index (RFC 9204 Appendix A),
// and the reverse. Only the codes a CONNECT-IP exchange produces are listed.
var statusStatic = map[string]uint64{
	"103": 24,
	"200": 25,
	"304": 26,
	"404": 27,
	"503": 28,
	"100": 63,
	"204": 64,
	"206": 65,
	"302": 66,
	"400": 67,
	"403": 68,
	"421": 69,
	"425": 70,
	"500": 71,
}

// staticByIndex resolves an absolute static index to a name/value, consulting
// both the general table and the status rows. ok is false for an index this
// subset does not carry, which the decoder treats as an error rather than
// guessing.
func staticByIndex(i uint64) (name, value string, ok bool) {
	// Names that are stable regardless of value.
	switch i {
	case 15:
		return ":method", "CONNECT", true
	case 17:
		return ":method", "GET", true
	case 20:
		return ":method", "POST", true
	case 22:
		return ":scheme", "http", true
	case 23:
		return ":scheme", "https", true
	case 1:
		return ":path", "/", true
	case 0:
		return ":authority", "", true
	}
	for v, idx := range statusStatic {
		if idx == i {
			return ":status", v, true
		}
	}
	return "", "", false
}

// staticIndexFor returns the absolute static index that exactly matches a
// name/value pair, if this subset carries one. Exact matches encode as a single
// byte, which is why CONNECT requests are compact.
func staticIndexFor(name, value string) (uint64, bool) {
	switch {
	case name == ":method" && value == "CONNECT":
		return 15, true
	case name == ":method" && value == "GET":
		return 17, true
	case name == ":scheme" && value == "https":
		return 23, true
	case name == ":scheme" && value == "http":
		return 22, true
	case name == ":path" && value == "/":
		return 1, true
	case name == ":authority" && value == "":
		return 0, true
	case name == ":status":
		if idx, ok := statusStatic[value]; ok {
			return idx, true
		}
	}
	return 0, false
}

// EncodeFieldSection encodes a header field section as a QPACK-encoded block,
// suitable for the body of an HTTP/3 HEADERS frame.
//
// The block opens with the field-section prefix: Required Insert Count and
// Delta Base, both zero because nothing references the dynamic table. Each field
// then encodes as a static-table reference when one matches exactly, and
// otherwise as a Literal Field Line With Literal Name — never Huffman, since
// leaving it off costs a few bytes on a request sent once and removes a whole
// encoder path.
func EncodeFieldSection(fields []Field) []byte {
	// Field-section prefix: Required Insert Count (0) and Base sign+Delta (0).
	out := []byte{0x00, 0x00}
	for _, f := range fields {
		if idx, ok := staticIndexFor(f.Name, f.Value); ok {
			// Indexed Field Line, static table: 1 T(=1 static) then a 6-bit
			// prefix integer. Pattern 1_1_xxxxxx.
			out = appendPrefixedInt(out, idx, 6, 0xc0)
			continue
		}
		// Literal Field Line With Literal Name (RFC 9204 §4.5.6). The first byte
		// is 001NHnnn: the 001 pattern, N (never-index, 0), H (huffman, 0 since
		// this encoder does not Huffman-code), and a 3-bit name-length prefix --
		// all one byte, which appendPrefixedInt writes with pattern 0x20. Then
		// the name octets, then the value as a 7-bit-prefix string literal.
		out = appendPrefixedInt(out, uint64(len(f.Name)), 3, 0x20)
		out = append(out, f.Name...)
		out = appendStringLiteral(out, f.Value)
	}
	return out
}

// appendPrefixedInt encodes v as an N-bit prefix integer (RFC 7541 §5.1, reused
// by QPACK), OR-ing the high pattern bits into the first byte. This is the
// integer form shared by every QPACK representation.
func appendPrefixedInt(dst []byte, v uint64, n uint, pattern byte) []byte {
	max := uint64(1<<n) - 1
	if v < max {
		return append(dst, pattern|byte(v))
	}
	dst = append(dst, pattern|byte(max))
	v -= max
	for v >= 128 {
		dst = append(dst, byte(v%128+128))
		v /= 128
	}
	return append(dst, byte(v))
}

// appendStringLiteral appends a QPACK string literal with a 7-bit length prefix
// and no Huffman coding (H bit clear).
func appendStringLiteral(dst []byte, s string) []byte {
	dst = appendPrefixedInt(dst, uint64(len(s)), 7, 0x00)
	return append(dst, s...)
}

// DecodeFieldSection decodes a QPACK-encoded field section into its fields.
func DecodeFieldSection(b []byte) ([]Field, error) {
	// Field-section prefix: Required Insert Count, then Base. This decoder keeps
	// no dynamic table, so a non-zero Required Insert Count means the peer is
	// referencing entries that cannot exist here.
	ric, b, err := readPrefixedInt(b, 8)
	if err != nil {
		return nil, err
	}
	if ric != 0 {
		return nil, fmt.Errorf("%w: required insert count %d", ErrQPACK, ric)
	}
	// Base: a sign bit then a 7-bit-prefix delta. With RIC 0 this is 0.
	if len(b) == 0 {
		return nil, ErrQPACK
	}
	_, b, err = readPrefixedInt(b, 7)
	if err != nil {
		return nil, err
	}

	var fields []Field
	for len(b) > 0 {
		switch {
		case b[0]&0x80 != 0:
			// Indexed Field Line. T bit (0x40) selects static vs dynamic.
			if b[0]&0x40 == 0 {
				return nil, fmt.Errorf("%w: dynamic indexed field line", ErrQPACK)
			}
			var idx uint64
			idx, b, err = readPrefixedInt(b, 6)
			if err != nil {
				return nil, err
			}
			name, value, ok := staticByIndex(idx)
			if !ok {
				return nil, fmt.Errorf("%w: unknown static index %d", ErrQPACK, idx)
			}
			fields = append(fields, Field{name, value})
		case b[0]&0x40 != 0:
			// Literal Field Line With Name Reference. T bit (0x10) static/dynamic.
			static := b[0]&0x10 != 0
			var idx uint64
			idx, b, err = readPrefixedInt(b, 4)
			if err != nil {
				return nil, err
			}
			if !static {
				return nil, fmt.Errorf("%w: dynamic name reference", ErrQPACK)
			}
			name, _, ok := staticByIndex(idx)
			if !ok {
				return nil, fmt.Errorf("%w: unknown static name index %d", ErrQPACK, idx)
			}
			var value string
			value, b, err = readStringLiteral(b)
			if err != nil {
				return nil, err
			}
			fields = append(fields, Field{name, value})
		case b[0]&0x20 != 0:
			// Literal Field Line With Literal Name.
			var name, value string
			name, b, err = readLiteralName(b)
			if err != nil {
				return nil, err
			}
			value, b, err = readStringLiteral(b)
			if err != nil {
				return nil, err
			}
			fields = append(fields, Field{name, value})
		default:
			return nil, fmt.Errorf("%w: unsupported representation %#02x", ErrQPACK, b[0])
		}
	}
	return fields, nil
}

// readLiteralName reads the name of a Literal Field Line With Literal Name: a
// 3-bit-prefix length (with an H bit at 0x08) then the octets.
func readLiteralName(b []byte) (string, []byte, error) {
	if len(b) == 0 {
		return "", b, ErrQPACK
	}
	huffman := b[0]&0x08 != 0
	n, rest, err := readPrefixedInt(b, 3)
	if err != nil {
		return "", b, err
	}
	if uint64(len(rest)) < n {
		return "", b, ErrQPACK
	}
	raw := rest[:n]
	rest = rest[n:]
	if huffman {
		dec, err := huffmanDecode(raw)
		if err != nil {
			return "", b, err
		}
		return dec, rest, nil
	}
	return string(raw), rest, nil
}

// readStringLiteral reads a QPACK string literal with a 7-bit length prefix and
// an H bit at 0x80.
func readStringLiteral(b []byte) (string, []byte, error) {
	if len(b) == 0 {
		return "", b, ErrQPACK
	}
	huffman := b[0]&0x80 != 0
	n, rest, err := readPrefixedInt(b, 7)
	if err != nil {
		return "", b, err
	}
	if uint64(len(rest)) < n {
		return "", b, ErrQPACK
	}
	raw := rest[:n]
	rest = rest[n:]
	if huffman {
		dec, err := huffmanDecode(raw)
		if err != nil {
			return "", b, err
		}
		return dec, rest, nil
	}
	return string(raw), rest, nil
}

// readPrefixedInt decodes an N-bit prefix integer, ignoring the pattern bits
// above the prefix in the first byte.
func readPrefixedInt(b []byte, n uint) (uint64, []byte, error) {
	if len(b) == 0 {
		return 0, b, ErrQPACK
	}
	max := uint64(1<<n) - 1
	v := uint64(b[0]) & max
	b = b[1:]
	if v < max {
		return v, b, nil
	}
	var m uint
	for {
		if len(b) == 0 {
			return 0, b, ErrQPACK
		}
		c := b[0]
		b = b[1:]
		v += uint64(c&0x7f) << m
		if c&0x80 == 0 {
			break
		}
		m += 7
		if m > 62 {
			return 0, b, ErrQPACK
		}
	}
	return v, b, nil
}
