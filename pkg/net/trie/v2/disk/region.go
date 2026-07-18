package disk

import (
	"io"
	"os"
)

// region is the platform-neutral read-only view of a segment file. Unix
// builds populate data with mmap; other platforms keep the file open and use
// small ReadAt calls for individual records.
type region struct {
	data []byte
	file *os.File
	size uint64
}

func (r *region) bytesAt(off, size uint64) ([]byte, bool) {
	if off > r.size || size > r.size-off {
		return nil, false
	}
	if r.data != nil {
		return r.data[off : off+size], true
	}

	buf := make([]byte, size)
	n, err := r.file.ReadAt(buf, int64(off))
	return buf, err == nil && uint64(n) == size
}

// close releases both the mapped bytes and the file descriptor. Keeping this
// operation on region makes segment lifecycle independent of the OS backend.
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

// writeAll handles short writes while constructing a segment or compaction
// output file.
func writeAll(f *os.File, data []byte) error {
	for len(data) != 0 {
		n, err := f.Write(data)
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
