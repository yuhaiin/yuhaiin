package vmess

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
)

type writer interface {
	io.WriteCloser
	io.ReaderFrom
}

type connWriter struct {
	net.Conn
}

func (c *connWriter) ReadFrom(r io.Reader) (int64, error) {
	return io.Copy(c.Conn, r)
}

const (
	lenSize          = 2
	maxChunkSize     = 1 << 14 // 16384
	defaultChunkSize = 1 << 13 // 8192
)

var _ writer = &aeadWriter{}

type chunkedWriter struct {
	io.Writer
	buf [lenSize + maxChunkSize]byte
}

// ChunkedWriter returns a chunked writer
func ChunkedWriter(w io.Writer) writer { return &chunkedWriter{Writer: w} }

func (w *chunkedWriter) Close() error { return nil }

func (w *chunkedWriter) Write(b []byte) (int, error) {
	n, err := w.ReadFrom(bytes.NewBuffer(b))
	return int(n), err
}

func (w *chunkedWriter) ReadFrom(r io.Reader) (n int64, err error) {
	for {
		nr, er := r.Read(w.buf[lenSize : lenSize+defaultChunkSize])
		if nr > 0 {
			n += int64(nr)
			binary.BigEndian.PutUint16(w.buf[:lenSize], uint16(nr))
			_, err = w.Writer.Write(w.buf[:lenSize+nr])
			if err != nil {
				// err = ew
				break
			}
		}

		if er != nil {
			if er != io.EOF { // ignore EOF as per io.ReaderFrom contract
				err = er
			}
			break
		}
	}

	return n, err
}

type chunkedReader struct {
	io.Reader
	leftBytes int
}

// ChunkedReader returns a chunked reader
func ChunkedReader(r io.Reader) io.ReadCloser { return &chunkedReader{Reader: r} }
func (r *chunkedReader) Close() error         { return nil }
func (r *chunkedReader) Read(b []byte) (int, error) {
	if r.leftBytes <= 0 {
		buf := utils.GetBytes(lenSize)
		defer utils.PutBytes(buf)

		// get length
		_, err := io.ReadFull(r.Reader, buf[:lenSize])
		if err != nil {
			return 0, err
		}
		r.leftBytes = int(binary.BigEndian.Uint16(buf[:lenSize]))

		// if length == 0, then this is the end
		if r.leftBytes <= 0 {
			return 0, nil
		}
	}

	m, err := r.Reader.Read(b)
	if err != nil {
		return 0, err
	}
	r.leftBytes -= m

	return m, nil
}
