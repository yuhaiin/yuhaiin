package nebula

// A minimal protobuf wire codec.
//
// Nebula's certificates and control messages are protobuf, but veepin depends
// on nothing outside golang.org/x/crypto, so the encoding is implemented here
// rather than generated. That is the same choice nebula itself makes for its
// handshake payload, whose .proto file notes it "is not run through protoc; the
// encoder/decoder ... is hand-written against this shape directly to keep the
// parser narrow and panic-free."
//
// Only what these messages actually use is implemented: varints, length
// delimited fields, and packed repeated uint32. Everything read here arrives
// from the network before anything has been authenticated, so every consume
// function bounds-checks and reports failure instead of panicking.
//
// Encoding must be byte-exact, not merely equivalent. A nebula certificate's
// signature covers the marshalled details, and the reference implementation
// verifies it by re-marshalling the parsed struct — so a field emitted in the
// wrong order, or a zero value emitted where protobuf-go would omit it, yields
// a certificate that veepin accepts and nebula rejects. The rules that keep the
// two in step: fields ascend by number, proto3 zero values are omitted, and
// repeated scalars are packed.

import "errors"

var errProto = errors.New("nebula: malformed protobuf")

// Protobuf wire types. Only the two that appear in these messages are defined.
const (
	wireVarint = 0
	wireBytes  = 2
)

// appendTag writes a field number and wire type.
func appendTag(b []byte, field int, wire uint64) []byte {
	return appendVarint(b, uint64(field)<<3|wire)
}

// appendVarint writes a base-128 varint, least significant group first.
func appendVarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

// appendBytes writes a length-delimited field body.
func appendBytes(b []byte, field int, v []byte) []byte {
	b = appendTag(b, field, wireBytes)
	b = appendVarint(b, uint64(len(v)))
	return append(b, v...)
}

// appendString writes a length-delimited string.
func appendString(b []byte, field int, v string) []byte {
	return appendBytes(b, field, []byte(v))
}

// appendUvarintField writes a varint-typed scalar.
func appendUvarintField(b []byte, field int, v uint64) []byte {
	b = appendTag(b, field, wireVarint)
	return appendVarint(b, v)
}

// appendPackedUint32 writes a repeated uint32 in packed form, which is what
// proto3 does by default and therefore what the signature covers.
func appendPackedUint32(b []byte, field int, vs []uint32) []byte {
	if len(vs) == 0 {
		return b
	}
	var packed []byte
	for _, v := range vs {
		packed = appendVarint(packed, uint64(v))
	}
	return appendBytes(b, field, packed)
}

// consumeVarint reads a varint, returning the value and the remaining buffer.
func consumeVarint(b []byte) (uint64, []byte, error) {
	var v uint64
	for i := range b {
		if i == 10 {
			// A varint wider than 64 bits cannot be represented and is a
			// protocol violation rather than a value to truncate.
			return 0, nil, errProto
		}
		v |= uint64(b[i]&0x7f) << (7 * uint(i))
		if b[i] < 0x80 {
			return v, b[i+1:], nil
		}
	}
	return 0, nil, errProto
}

// consumeTag reads a field number and wire type.
func consumeTag(b []byte) (field int, wire uint64, rest []byte, err error) {
	v, rest, err := consumeVarint(b)
	if err != nil {
		return 0, 0, nil, err
	}
	field = int(v >> 3)
	if field <= 0 {
		return 0, 0, nil, errProto
	}
	return field, v & 0x7, rest, nil
}

// consumeBytes reads a length-delimited field body. The result aliases b; the
// callers that retain a value copy it.
func consumeBytes(b []byte) ([]byte, []byte, error) {
	n, rest, err := consumeVarint(b)
	if err != nil {
		return nil, nil, err
	}
	if n > uint64(len(rest)) {
		return nil, nil, errProto
	}
	return rest[:n], rest[n:], nil
}

// consumePackedUint32 reads a packed repeated uint32 field body.
func consumePackedUint32(body []byte) ([]uint32, error) {
	var out []uint32
	for len(body) > 0 {
		v, rest, err := consumeVarint(body)
		if err != nil {
			return nil, err
		}
		if v > 0xffffffff {
			return nil, errProto
		}
		out = append(out, uint32(v))
		body = rest
	}
	return out, nil
}

// skipField advances past a field whose number the caller does not recognise,
// so that unknown fields from a newer peer are tolerated rather than fatal.
func skipField(wire uint64, b []byte) ([]byte, error) {
	switch wire {
	case wireVarint:
		_, rest, err := consumeVarint(b)
		return rest, err
	case wireBytes:
		_, rest, err := consumeBytes(b)
		return rest, err
	case 5: // fixed32
		if len(b) < 4 {
			return nil, errProto
		}
		return b[4:], nil
	case 1: // fixed64
		if len(b) < 8 {
			return nil, errProto
		}
		return b[8:], nil
	default:
		// Group wire types were removed in proto3 and nothing here emits them.
		return nil, errProto
	}
}
