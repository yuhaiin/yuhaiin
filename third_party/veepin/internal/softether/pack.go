// Package softether implements the wire format of the SoftEther VPN native
// protocol (SE-VPN): Ethernet frames over TLS with a self-describing key/value
// serialisation called "PACK" for control messages, and raw Ethernet frames for
// data.
//
// PACK format, from SoftEtherVPN/src/Mayaqua/Pack.c (WritePack, WriteElement,
// WriteValue) and src/Mayaqua/Memory.c (WriteBufInt, WriteBufStr):
//
//   - **Big-endian integers throughout.** Every integer goes through
//     WriteBufInt/ReadBufInt, which call Endian32, which byte-swaps on a
//     little-endian host -- so the wire is network order. This package had it
//     little-endian in both directions for as long as it existed, which two
//     veepin endpoints agree on perfectly and no SoftEther server does.
//   - Header: element-count uint32, then that many ELEMENTs.
//   - ELEMENT:
//     name:   uint32 length-PLUS-ONE, then length bytes of ASCII, no NUL.
//     type:   uint32 (0=INT, 1=DATA, 2=STR, 3=UNISTR, 4=INT64).
//     count:  uint32 (number of values).
//     values: count × VALUE, each depending on type.
//   - VALUE types:
//     INT:    uint32 (4 bytes).
//     INT64:  uint64 (8 bytes).
//     DATA:   length uint32, then length bytes of raw data.
//     STR:    length uint32, then length bytes of ASCII, no NUL.
//     UNISTR: length uint32 counting a NUL, then that many bytes of UTF-8
//     with the NUL included.
//
// The three string encodings disagree with each other and each one is right:
// a name counts a terminator it does not send, a STR neither counts nor sends
// one, and a UNISTR does both. That is not a summary anyone would arrive at
// without reading WriteBufStr and WriteValue side by side.
//
// Control PACKs do not sit on the connection directly -- each one is the body
// of an HTTP message (see http.go), and the data path that follows them has
// its own framing (see frame.go). A PACK is only ever the payload.
package softether

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// Element value type constants, matching SoftEther's VALUE_* defines.
const (
	TypeInt    = 0
	TypeData   = 1
	TypeStr    = 2
	TypeUniStr = 3
	TypeInt64  = 4
)

// Limits matching SoftEther's MAX_* defines (64-bit platform values).
const (
	MaxElementNameLen = 63
	MaxValueSize      = 384 * 1024 * 1024 // per VALUE
	MaxValueNum       = 262144            // per ELEMENT
	MaxElementNum     = 262144            // per PACK
	MaxPackSize       = 512 * 1024 * 1024
)

var (
	ErrTruncated       = errors.New("softether: truncated PACK data")
	ErrTooManyElements = errors.New("softether: too many elements")
	ErrTooManyValues   = errors.New("softether: too many values")
	ErrValueTooLarge   = errors.New("softether: value too large")
	ErrUnknownType     = errors.New("softether: unknown element type")
	ErrNameTooLong     = errors.New("softether: element name too long")
)

// Pack is a self-describing key/value container used for SoftEther control
// messages. It maps names to elements, where each element has a type and one
// or more values (arrays).
type Pack struct {
	elems []Element
}

// Element is a named collection of typed values.
type Element struct {
	Name   string
	Type   int
	Values []Value
}

// Value holds a single value of one of the five PACK types.
type Value struct {
	Int    uint32
	Int64  uint64
	Data   []byte
	Str    string
	UniStr string // stored as Go string (UTF-8 on wire)
}

// NewPack returns an empty Pack.
func NewPack() *Pack { return &Pack{} }

// Add appends a single-valued element.
func (p *Pack) Add(name string, typ int, v Value) {
	p.elems = append(p.elems, Element{Name: name, Type: typ, Values: []Value{v}})
}

// AddMulti appends a multi-valued element.
func (p *Pack) AddMulti(name string, typ int, vals []Value) {
	p.elems = append(p.elems, Element{Name: name, Type: typ, Values: vals})
}

// Get returns the first element with the given name, or nil.
func (p *Pack) Get(name string) *Element {
	for i := range p.elems {
		if p.elems[i].Name == name {
			return &p.elems[i]
		}
	}
	return nil
}

// GetInt returns the int value of a named element, or 0.
func (p *Pack) GetInt(name string) uint32 {
	if e := p.Get(name); e != nil && e.Type == TypeInt && len(e.Values) > 0 {
		return e.Values[0].Int
	}
	return 0
}

// GetStr returns the string value of a named element, or "".
func (p *Pack) GetStr(name string) string {
	if e := p.Get(name); e != nil && e.Type == TypeStr && len(e.Values) > 0 {
		return e.Values[0].Str
	}
	return ""
}

// GetUniStr returns the Unicode-string value of a named element, or "".
//
// Separate from GetStr because the two are distinct types on the wire and a
// peer picks one per field: SoftEther sends the hub and user names as STR and
// the human-facing text (a server's own description, a disconnect reason) as
// UNISTR. Asking for the wrong one returns "" rather than converting, so a
// caller that guesses gets an empty string instead of silently working.
func (p *Pack) GetUniStr(name string) string {
	if e := p.Get(name); e != nil && e.Type == TypeUniStr && len(e.Values) > 0 {
		return e.Values[0].UniStr
	}
	return ""
}

// GetData returns the data value of a named element, or nil.
func (p *Pack) GetData(name string) []byte {
	if e := p.Get(name); e != nil && e.Type == TypeData && len(e.Values) > 0 {
		return e.Values[0].Data
	}
	return nil
}

// Encode serialises the Pack into bytes.
func (p *Pack) Encode() ([]byte, error) {
	if len(p.elems) > MaxElementNum {
		return nil, ErrTooManyElements
	}
	// Upper bound: 4 (count) + sum of element sizes.
	// Each element: name (up to 65), type(4), count(4) + values.
	size := 4
	for _, e := range p.elems {
		size += 4 + len(e.Name) + 4 + 4 // name length+body + type + count
		for _, v := range e.Values {
			size += valueWireSize(e.Type, v)
		}
	}
	if size > MaxPackSize {
		return nil, ErrValueTooLarge
	}
	b := make([]byte, 0, size)
	b = binary.BigEndian.AppendUint32(b, uint32(len(p.elems)))
	for _, e := range p.elems {
		if len(e.Name) > MaxElementNameLen {
			return nil, ErrNameTooLong
		}
		b = appendName(b, e.Name)
		b = binary.BigEndian.AppendUint32(b, uint32(e.Type))
		b = binary.BigEndian.AppendUint32(b, uint32(len(e.Values)))
		for _, v := range e.Values {
			var err error
			b, err = appendValue(b, e.Type, v)
			if err != nil {
				return nil, err
			}
		}
	}
	return b, nil
}

// Decode parses a Pack from bytes. It returns subslices of the input — no
// allocation per element for the data/str bodies (strings are still allocated
// by Go's type system).
func Decode(buf []byte) (*Pack, error) {
	orig := buf
	if len(buf) < 4 {
		return nil, ErrTruncated
	}
	count := binary.BigEndian.Uint32(buf)
	buf = buf[4:]
	if count > MaxElementNum {
		return nil, ErrTooManyElements
	}
	p := &Pack{elems: make([]Element, 0, count)}
	for range count {
		e, err := decodeElement(&buf)
		if err != nil {
			return nil, err
		}
		p.elems = append(p.elems, e)
	}
	_ = orig // keep reference to the backing array
	return p, nil
}

func decodeElement(buf *[]byte) (Element, error) {
	// Name: a length that counts a NUL which is never sent. See readName.
	name, err := readName(buf)
	if err != nil {
		return Element{}, err
	}
	if len(*buf) < 8 {
		return Element{}, ErrTruncated
	}
	typ := binary.BigEndian.Uint32((*buf)[:4])
	*buf = (*buf)[4:]
	nv := binary.BigEndian.Uint32((*buf)[:4])
	*buf = (*buf)[4:]

	if nv > MaxValueNum {
		return Element{}, ErrTooManyValues
	}
	e := Element{Name: name, Type: int(typ)}
	e.Values = make([]Value, nv)
	for i := range nv {
		v, err := decodeValue(buf, int(typ))
		if err != nil {
			return Element{}, err
		}
		e.Values[i] = v
	}
	return e, nil
}

func decodeValue(buf *[]byte, typ int) (Value, error) {
	switch typ {
	case TypeInt:
		if len(*buf) < 4 {
			return Value{}, ErrTruncated
		}
		v := binary.BigEndian.Uint32((*buf)[:4])
		*buf = (*buf)[4:]
		return Value{Int: v}, nil

	case TypeInt64:
		if len(*buf) < 8 {
			return Value{}, ErrTruncated
		}
		v := binary.BigEndian.Uint64((*buf)[:8])
		*buf = (*buf)[8:]
		return Value{Int64: v}, nil

	case TypeData:
		if len(*buf) < 4 {
			return Value{}, ErrTruncated
		}
		sz := binary.BigEndian.Uint32((*buf)[:4])
		*buf = (*buf)[4:]
		if sz > MaxValueSize {
			return Value{}, ErrValueTooLarge
		}
		if uint32(len(*buf)) < sz {
			return Value{}, ErrTruncated
		}
		// Return subslice of the input — no copy.
		v := (*buf)[:sz]
		*buf = (*buf)[sz:]
		return Value{Data: v}, nil

	case TypeStr:
		if len(*buf) < 4 {
			return Value{}, ErrTruncated
		}
		sz := binary.BigEndian.Uint32((*buf)[:4])
		*buf = (*buf)[4:]
		if sz > MaxValueSize {
			return Value{}, ErrValueTooLarge
		}
		if uint32(len(*buf)) < sz {
			return Value{}, ErrTruncated
		}
		s := string((*buf)[:sz])
		*buf = (*buf)[sz:]
		return Value{Str: s}, nil

	case TypeUniStr:
		if len(*buf) < 4 {
			return Value{}, ErrTruncated
		}
		sz := binary.BigEndian.Uint32((*buf)[:4])
		*buf = (*buf)[4:]
		if sz > MaxValueSize {
			return Value{}, ErrValueTooLarge
		}
		if uint32(len(*buf)) < sz {
			return Value{}, ErrTruncated
		}
		body := (*buf)[:sz]
		*buf = (*buf)[sz:]
		// Trim the terminator the encoder counted and sent. A peer that sends
		// a bare length with no NUL still parses; keeping it would put a stray
		// 0x00 inside every string this side compares.
		body = bytes.TrimSuffix(body, []byte{0})
		return Value{UniStr: string(body)}, nil

	default:
		return Value{}, fmt.Errorf("%w: %d", ErrUnknownType, typ)
	}
}

func valueWireSize(typ int, v Value) int {
	switch typ {
	case TypeInt:
		return 4
	case TypeInt64:
		return 8
	case TypeData:
		return 4 + len(v.Data)
	case TypeStr:
		return 4 + len(v.Str)
	case TypeUniStr:
		return 4 + len(v.UniStr) + 1 // + the NUL this one carries
	default:
		return 0
	}
}

func appendValue(b []byte, typ int, v Value) ([]byte, error) {
	switch typ {
	case TypeInt:
		return binary.BigEndian.AppendUint32(b, v.Int), nil
	case TypeInt64:
		return binary.BigEndian.AppendUint64(b, v.Int64), nil
	case TypeData:
		if uint32(len(v.Data)) > MaxValueSize {
			return nil, ErrValueTooLarge
		}
		b = binary.BigEndian.AppendUint32(b, uint32(len(v.Data)))
		return append(b, v.Data...), nil
	case TypeStr:
		if len(v.Str) > MaxValueSize {
			return nil, ErrValueTooLarge
		}
		b = binary.BigEndian.AppendUint32(b, uint32(len(v.Str)))
		return append(b, v.Str...), nil
	case TypeUniStr:
		// UTF-8 on the wire, and the one string here that DOES carry its NUL:
		// WriteValue writes CalcUniToUtf8()+1 octets and the terminator with
		// them, where VALUE_STR just above writes the length and no NUL. Three
		// string encodings in one format, all different -- element names count
		// a NUL they omit, STR omits both, UNISTR counts and sends one.
		utf8 := v.UniStr
		if uint32(len(utf8))+1 > MaxValueSize {
			return nil, ErrValueTooLarge
		}
		b = binary.BigEndian.AppendUint32(b, uint32(len(utf8))+1)
		b = append(b, utf8...)
		return append(b, 0), nil
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnknownType, typ)
	}
}

// appendName writes an element name the way WriteBufStr does: a uint32 length
// that is the string length PLUS ONE, then the string body WITHOUT the NUL the
// extra octet accounts for. The count and the bytes that follow it disagree by
// one, deliberately, and both ends have to make the same allowance.
func appendName(b []byte, name string) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(name))+1)
	return append(b, name...)
}

// readName is appendName's inverse. A zero length is refused rather than
// wrapping to 0xffffffff on the decrement -- ReadBufStr rejects it too, and it
// is the first thing a fuzzer finds.
func readName(buf *[]byte) (string, error) {
	if len(*buf) < 4 {
		return "", ErrTruncated
	}
	n := binary.BigEndian.Uint32((*buf)[:4])
	*buf = (*buf)[4:]
	if n == 0 {
		return "", ErrTruncated
	}
	n-- // the NUL that is counted and not sent
	if n > MaxElementNameLen {
		return "", ErrNameTooLong
	}
	if uint32(len(*buf)) < n {
		return "", ErrTruncated
	}
	s := string((*buf)[:n])
	*buf = (*buf)[n:]
	return s, nil
}

// IntValue returns a Value containing a uint32.
func IntValue(v uint32) Value { return Value{Int: v} }

// Int64Value returns a Value containing a uint64.
func Int64Value(v uint64) Value { return Value{Int64: v} }

// DataValue returns a Value containing a byte slice.
func DataValue(v []byte) Value { return Value{Data: v} }

// StrValue returns a Value containing a string.
func StrValue(v string) Value { return Value{Str: v} }

// UniStrValue returns a Value containing a Unicode string (UTF-8).
func UniStrValue(v string) Value { return Value{UniStr: v} }
