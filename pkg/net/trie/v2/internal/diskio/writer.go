// Package diskio provides bounded buffering for immutable trie construction.
package diskio

import (
	"errors"
	"io"
)

const BufferSize = 64 << 10

// WriterAt coalesces adjacent records and patches within the current window.
// It only writes initialized bytes; gaps and seeks flush the previous window.
// Use separate writers for disjoint file sections and Flush before syncing or
// reading the underlying file. It is not safe for concurrent use.
type WriterAt struct {
	writer io.WriterAt
	data   []byte
	offset int64
}

func NewWriterAt(writer io.WriterAt) *WriterAt { return &WriterAt{writer: writer} }

func (w *WriterAt) WriteAt(data []byte, offset int64) (int, error) {
	if offset < 0 || int64(len(data)) > int64(^uint64(0)>>1)-offset {
		return 0, errors.New("invalid buffered write offset")
	}
	written := 0
	for len(data) != 0 {
		if len(w.data) != 0 && (offset < w.offset || offset > w.offset+int64(len(w.data)) || offset-w.offset >= BufferSize) {
			if err := w.Flush(); err != nil {
				return written, err
			}
		}
		if len(w.data) == 0 {
			w.offset = offset
		}
		if w.data == nil {
			w.data = make([]byte, 0, BufferSize)
		}
		start := int(offset - w.offset)
		size := min(len(data), BufferSize-start)
		end := start + size
		if end > len(w.data) {
			w.data = w.data[:end]
		}
		// Always copy, including large values. Keeping caller data away from the
		// underlying interface lets fixed-size record buffers stay on the stack.
		copy(w.data[start:], data[:size])
		written += size
		offset += int64(size)
		data = data[size:]
		if len(w.data) == BufferSize {
			if err := w.Flush(); err != nil {
				return written, err
			}
		}
	}
	return written, nil
}

func (w *WriterAt) Flush() error {
	if len(w.data) == 0 {
		return nil
	}
	n, err := w.writer.WriteAt(w.data, w.offset)
	if err != nil {
		return err
	}
	if n != len(w.data) {
		return io.ErrShortWrite
	}
	w.data = w.data[:0]
	return nil
}
