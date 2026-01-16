package codec

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"unsafe"
)

type Codec[T comparable] interface {
	Encode([]T) ([]byte, error)
	Decode([]byte) ([]T, error)
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

func (UnsafeStringCodec) Encode(vals []string) ([]byte, error) {
	total := 4
	for _, s := range vals {
		total += 4 + len(s)
	}

	buf := make([]byte, total)
	binary.LittleEndian.PutUint32(buf[:4], uint32(len(vals)))

	off := 4
	for _, s := range vals {
		b := unsafe.Slice(unsafe.StringData(s), len(s))

		binary.LittleEndian.PutUint32(buf[off:], uint32(len(b)))
		off += 4
		copy(buf[off:], b)
		off += len(b)
	}
	return buf, nil
}

func (UnsafeStringCodec) Decode(data []byte) ([]string, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("data too short")
	}
	n := int(binary.LittleEndian.Uint32(data[:4]))
	res := make([]string, n)

	off := 4
	for i := range n {
		l := int(binary.LittleEndian.Uint32(data[off:]))
		off += 4

		res[i] = unsafe.String(&data[off], l)
		off += l
	}
	return res, nil
}
