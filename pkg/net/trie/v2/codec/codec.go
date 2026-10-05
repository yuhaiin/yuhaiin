package codec

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"slices"
	"strings"
	"unsafe"
)

type Codec[T comparable] interface {
	Encode([]T) ([]byte, error)
	Decode([]byte) ([]T, error)
}

// AppendEncoder writes an encoding into caller-owned reusable storage.
type AppendEncoder[T comparable] interface {
	AppendEncode([]byte, []T) ([]byte, error)
}

// EncodedSizer reports the exact size without allocating an encoding.
type EncodedSizer[T comparable] interface{ EncodedSize([]T) uint64 }

func AppendEncode[T comparable](c Codec[T], dst []byte, values []T) ([]byte, error) {
	if encoder, ok := c.(AppendEncoder[T]); ok {
		return encoder.AppendEncode(dst, values)
	}
	encoded, err := c.Encode(values)
	if err != nil {
		return dst, err
	}
	return append(dst, encoded...), nil
}

// AppendDecoder can decode directly into an owned, deduplicated result.
type AppendDecoder[T comparable] interface {
	AppendDecodeOwned([]T, []byte) ([]T, error)
}

// AppendUniqueOwned preserves result order and detaches mmap-backed strings.
// On error it returns the original result rather than partially decoded values.
func AppendUniqueOwned[T comparable](c Codec[T], dst []T, data []byte) ([]T, error) {
	if decoder, ok := c.(AppendDecoder[T]); ok {
		return decoder.AppendDecodeOwned(dst, data)
	}
	values, err := c.Decode(data)
	if err != nil {
		return dst, err
	}
	for _, value := range values {
		if slices.Contains(dst, value) {
			continue
		}
		if text, ok := any(value).(string); ok {
			value = any(strings.Clone(text)).(T)
		}
		dst = append(dst, value)
	}
	return dst, nil
}

type GobCodec[T comparable] struct{}

func (GobCodec[T]) Encode(v []T) ([]byte, error) {
	var buf bytes.Buffer
	err := gob.NewEncoder(&buf).Encode(v)
	return buf.Bytes(), err
}

func (GobCodec[T]) Decode(b []byte) ([]T, error) {
	var v []T
	err := gob.NewDecoder(bytes.NewReader(b)).Decode(&v)
	return v, err
}

type UnsafeStringCodec struct{}

func (c UnsafeStringCodec) Encode(values []string) ([]byte, error) {
	return c.AppendEncode(nil, values)
}

func (UnsafeStringCodec) EncodedSize(values []string) uint64 {
	size := uint64(4)
	for _, value := range values {
		size += 4 + uint64(len(value))
	}
	return size
}

func (c UnsafeStringCodec) AppendEncode(dst []byte, values []string) ([]byte, error) {
	start := len(dst)
	size := int(c.EncodedSize(values))
	if size <= cap(dst)-start {
		dst = dst[:start+size]
	} else {
		dst = append(dst, make([]byte, size)...)
	}
	buffer := dst[start:]
	binary.LittleEndian.PutUint32(buffer, uint32(len(values)))
	offset := 4
	for _, value := range values {
		binary.LittleEndian.PutUint32(buffer[offset:], uint32(len(value)))
		offset += 4
		copy(buffer[offset:], value)
		offset += len(value)
	}
	return dst, nil
}

func (UnsafeStringCodec) Decode(data []byte) ([]string, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("data too short")
	}
	n := uint64(binary.LittleEndian.Uint32(data[:4]))
	if n > uint64((len(data)-4)/4) {
		return nil, fmt.Errorf("invalid string count")
	}
	res := make([]string, n)

	off := 4
	for i := range res {
		if len(data)-off < 4 {
			return nil, fmt.Errorf("truncated string length")
		}
		l := uint64(binary.LittleEndian.Uint32(data[off:]))
		off += 4
		if l > uint64(len(data)-off) {
			return nil, fmt.Errorf("truncated string value")
		}
		if l != 0 {
			res[i] = unsafe.String(unsafe.SliceData(data[off:off+int(l)]), int(l))
		}
		off += int(l)
	}
	if off != len(data) {
		return nil, fmt.Errorf("trailing string data")
	}
	return res, nil
}

// AppendDecodeOwned avoids a temporary []string and copies only new marks.
func (UnsafeStringCodec) AppendDecodeOwned(dst []string, data []byte) ([]string, error) {
	return appendStringValues(dst, data, nil)
}

func appendStringValues(dst []string, data []byte, pool map[string]string) ([]string, error) {
	original := dst
	if len(data) < 4 {
		return original, fmt.Errorf("data too short")
	}
	count := uint64(binary.LittleEndian.Uint32(data))
	if count > uint64((len(data)-4)/4) {
		return original, fmt.Errorf("invalid string count")
	}
	offset := 4
	for range count {
		if len(data)-offset < 4 {
			return original, fmt.Errorf("truncated string length")
		}
		size := uint64(binary.LittleEndian.Uint32(data[offset:]))
		offset += 4
		if size > uint64(len(data)-offset) {
			return original, fmt.Errorf("truncated string value")
		}
		value := ""
		if size != 0 {
			value = unsafe.String(unsafe.SliceData(data[offset:offset+int(size)]), int(size))
		}
		if !slices.Contains(dst, value) {
			owned, ok := pool[value]
			if !ok {
				owned = strings.Clone(value)
			}
			dst = append(dst, owned)
		}
		offset += int(size)
	}
	if offset != len(data) {
		return original, fmt.Errorf("trailing string data")
	}
	return dst, nil
}
