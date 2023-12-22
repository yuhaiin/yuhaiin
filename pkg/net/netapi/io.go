package netapi

import (
	"io"
	"unsafe"
)

type Reader struct {
	io.Reader
}

func NewReader(r io.Reader) *Reader {
	return &Reader{r}
}

func (r *Reader) ReadByte() (byte, error) {
	b := make([]byte, 1)
	_, err := r.Read(b)
	return b[0], err
}

func (r *Reader) ReadBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}

type Writer struct {
	io.Writer
}

func NewWriter(w io.Writer) *Writer {
	return &Writer{w}
}

func (w *Writer) WriteByte(b byte) error {
	_, err := w.Write([]byte{b})
	return err
}

func (w *Writer) WriteString(b string) (int, error) {
	return w.Write(unsafe.Slice(unsafe.StringData(b), len(b)))
}
