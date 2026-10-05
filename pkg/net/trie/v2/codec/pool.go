package codec

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"unsafe"
)

const (
	stringPoolEntries = 1024
	stringPoolBytes   = 64 << 10
	stringPoolBuffer  = 4 << 10
)

// PooledStringCodec shares a bounded, immutable dictionary of owned marks.
// It keeps the original string encoding and is safe for concurrent readers.
// Build it before publishing a segment; queries never mutate the dictionary.
type PooledStringCodec struct {
	UnsafeStringCodec
	values map[string]string
}

// NewPooledStringCodec scans concatenated UnsafeStringCodec value blocks.
// A nil codec and nil error means pooling would exceed the fixed limits; the
// caller should retain the ordinary codec. No whole-index copy is retained.
func NewPooledStringCodec(source io.Reader) (*PooledStringCodec, error) {
	reader := bufio.NewReaderSize(source, 64<<10)
	values := make(map[string]string)
	used := 0
	for {
		header, err := reader.Peek(4)
		if err != nil {
			if err == io.EOF && len(header) == 0 {
				return &PooledStringCodec{values: values}, nil
			}
			return nil, fmt.Errorf("truncated pooled string count: %w", err)
		}
		count := binary.LittleEndian.Uint32(header)
		reader.Discard(4)
		for range count {
			header, err := reader.Peek(4)
			if err != nil {
				return nil, fmt.Errorf("truncated pooled string length: %w", err)
			}
			size := uint64(binary.LittleEndian.Uint32(header))
			reader.Discard(4)
			if size > stringPoolBuffer {
				return nil, nil
			}
			data, err := reader.Peek(int(size))
			if err != nil {
				return nil, fmt.Errorf("truncated pooled string: %w", err)
			}
			value := ""
			if len(data) != 0 {
				value = unsafe.String(unsafe.SliceData(data), len(data))
			}
			if _, ok := values[value]; !ok {
				if len(values) == stringPoolEntries || used+len(value) > stringPoolBytes {
					return nil, nil
				}
				owned := strings.Clone(value)
				values[owned] = owned
				used += len(owned)
			}
			reader.Discard(int(size))
		}
	}
}

func (c *PooledStringCodec) Decode(data []byte) ([]string, error) {
	values, err := c.UnsafeStringCodec.Decode(data)
	if err != nil {
		return nil, err
	}
	for index, value := range values {
		owned, ok := c.values[value]
		if !ok {
			owned = strings.Clone(value)
		}
		values[index] = owned
	}
	return values, nil
}

func (c *PooledStringCodec) AppendDecodeOwned(dst []string, data []byte) ([]string, error) {
	return appendStringValues(dst, data, c.values)
}
