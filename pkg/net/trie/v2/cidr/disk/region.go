package disk

import (
	"io"
	"os"
)

// region provides bounded reads over a segment. Unix builds may map it while
// other platforms use ReadAt and rely on the operating system file cache.
type region struct {
	data []byte
	file *os.File
	size uint64
}

func (r *region) bytesAt(offset, size uint64) ([]byte, bool) {
	if offset > r.size || size > r.size-offset {
		return nil, false
	}
	if r.data != nil {
		return r.data[offset : offset+size], true
	}
	data := make([]byte, size)
	n, err := r.file.ReadAt(data, int64(offset))
	return data, err == nil && uint64(n) == size
}

func (r *region) close() error {
	if r == nil {
		return nil
	}
	err := unmapBytes(r.data)
	r.data = nil
	if r.file != nil {
		if closeErr := r.file.Close(); err == nil {
			err = closeErr
		}
		r.file = nil
	}
	return err
}

func writeAll(file *os.File, data []byte) error {
	for len(data) != 0 {
		n, err := file.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
