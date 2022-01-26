package vmess

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
)

const (
	lenSize          = 2
	maxChunkSize     = 1 << 14 // 16384
	defaultChunkSize = 1 << 13 // 8192
)

var _ io.WriteCloser = &aeadWriter{}

type chunkedWriter struct {
	io.Writer
	buf []byte
}

// ChunkedWriter returns a chunked writer
func ChunkedWriter(w io.Writer) io.WriteCloser {
	return &chunkedWriter{
		Writer: w,
		buf:    utils.GetBytes(lenSize + maxChunkSize),
	}
}

func (w *chunkedWriter) Close() error {
	utils.PutBytes(lenSize+maxChunkSize, &w.buf)
	return nil
}

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
	buf       []byte
	leftBytes int
}

// ChunkedReader returns a chunked reader
func ChunkedReader(r io.Reader) io.ReadCloser {
	return &chunkedReader{
		Reader: r,
		buf:    utils.GetBytes(lenSize), // NOTE: buf only used to save header bytes now
	}
}

func (r *chunkedReader) Close() error {
	utils.PutBytes(lenSize, &r.buf)
	return nil
}

func (r *chunkedReader) Read(b []byte) (int, error) {
	if r.leftBytes == 0 {
		// get length
		_, err := io.ReadFull(r.Reader, r.buf[:lenSize])
		if err != nil {
			return 0, err
		}
		r.leftBytes = int(binary.BigEndian.Uint16(r.buf[:lenSize]))

		// if length == 0, then this is the end
		if r.leftBytes == 0 {
			return 0, nil
		}
	}

	readLen := len(b)
	if readLen > r.leftBytes {
		readLen = r.leftBytes
	}

	m, err := r.Reader.Read(b[:readLen])
	if err != nil {
		return 0, err
	}

	r.leftBytes -= m
	return m, err
}
