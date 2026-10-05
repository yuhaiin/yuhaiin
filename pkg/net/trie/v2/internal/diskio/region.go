package diskio

import (
	"bytes"
	"io"
	"os"
)

// Region is the platform-neutral read-only view of a segment file. Unix
// builds populate data with mmap; other platforms keep the file open and use
// small ReadAt calls for individual records.
type Region struct {
	data []byte
	file *os.File
	Size uint64
}

func (r *Region) BytesAt(off, size uint64) ([]byte, bool) {
	if off > r.Size || size > r.Size-off {
		return nil, false
	}
	if r.data != nil {
		return r.data[off : off+size], true
	}
	if r.file == nil {
		return nil, false
	}

	buf := make([]byte, size)
	n, err := r.file.ReadAt(buf, int64(off))
	return buf, err == nil && uint64(n) == size
}

// MappedBytes returns a borrowed view only on the mmap backend. It never
// falls back to reading the entire section into heap memory.
func (r *Region) MappedBytes(off, size uint64) ([]byte, bool) {
	if r.data == nil || off > r.Size || size > r.Size-off {
		return nil, false
	}
	return r.data[off : off+size], true
}

// Reader streams a file section without copying the entire mmap or ReadAt
// area into Go memory. The caller must keep the Region open until reading ends.
func (r *Region) Reader(off, size uint64) (io.Reader, bool) {
	if off > r.Size || size > r.Size-off {
		return nil, false
	}
	// Sequential initialization should not fault every scanned mmap page into
	// the process working set. A buffered file reader keeps this cost bounded.
	if r.file != nil {
		return io.NewSectionReader(r.file, int64(off), int64(size)), true
	}
	if r.data != nil {
		return bytes.NewReader(r.data[off : off+size]), true
	}
	return nil, false
}

// Close releases both the mapped bytes and the file descriptor. Keeping this
// operation on region makes segment lifecycle independent of the OS backend.
func (r *Region) Close() error {
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

// WriteAll handles short writes while constructing a segment or compaction
// output file.
func WriteAll(f io.Writer, data []byte) error {
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
