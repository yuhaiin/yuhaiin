package vmess

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"io"

	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
)

var _ io.WriteCloser = &aeadWriter{}

type aeadWriter struct {
	io.Writer
	cipher.AEAD
	nonce []byte
	buf   []byte
	count uint16
	iv    []byte
}

// AEADWriter returns a aead writer
func AEADWriter(w io.Writer, aead cipher.AEAD, iv []byte) writer {
	return &aeadWriter{
		Writer: w,
		AEAD:   aead,
		buf:    utils.GetBytes(lenSize + maxChunkSize),
		nonce:  utils.GetBytes(aead.NonceSize()),
		count:  0,
		iv:     iv,
	}
}

func (w *aeadWriter) Close() error {
	utils.PutBytes(w.buf)
	utils.PutBytes(w.nonce)
	return nil
}

func (w *aeadWriter) Write(b []byte) (int, error) {
	n, err := w.ReadFrom(bytes.NewBuffer(b))
	return int(n), err
}

func (w *aeadWriter) ReadFrom(r io.Reader) (n int64, err error) {
	for {
		payloadBuf := w.buf[lenSize : lenSize+defaultChunkSize-w.Overhead()]

		nr, er := r.Read(payloadBuf)
		if nr > 0 {
			n += int64(nr)
			w.buf = w.buf[:lenSize+nr+w.Overhead()]
			payloadBuf = payloadBuf[:nr]
			binary.BigEndian.PutUint16(w.buf[:lenSize], uint16(nr+w.Overhead()))

			binary.BigEndian.PutUint16(w.nonce[:2], w.count)
			copy(w.nonce[2:], w.iv[2:12])

			w.Seal(payloadBuf[:0], w.nonce[:w.NonceSize()], payloadBuf, nil)
			w.count++

			_, ew := w.Writer.Write(w.buf)
			if ew != nil {
				err = ew
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

var _ io.ReadCloser = &aeadReader{}

type aeadReader struct {
	io.Reader
	cipher.AEAD
	nonce   []byte
	buf     []byte
	offset  int
	dataLen int
	lenBuf  []byte
	count   uint16
	iv      []byte
}

// AEADReader returns a aead reader
func AEADReader(r io.Reader, aead cipher.AEAD, iv []byte) io.ReadCloser {
	return &aeadReader{
		Reader: r,
		AEAD:   aead,
		lenBuf: utils.GetBytes(lenSize),
		nonce:  utils.GetBytes(aead.NonceSize()),
		count:  0,
		iv:     iv,
	}
}

func (r *aeadReader) Close() error {
	utils.PutBytes(r.lenBuf)
	utils.PutBytes(r.nonce)
	return nil
}

func (r *aeadReader) Read(b []byte) (int, error) {
	if r.offset != r.dataLen {
		// logasfmt.Println(r.offset, r.dataLen)
		n := copy(b, r.buf[r.offset:r.dataLen])
		r.offset += n
		if r.offset == r.dataLen {
			utils.PutBytes(r.buf)
			r.buf = nil
		}
		return n, nil
	}

	// get length
	_, err := io.ReadFull(r.Reader, r.lenBuf)
	if err != nil {
		return 0, err
	}

	// if length == 0, then this is the end
	l := binary.BigEndian.Uint16(r.lenBuf)
	if l == 0 {
		return 0, nil
	}

	r.buf = utils.GetBytes(int(l))
	// logasfmt.Println(l, len(r.buf))
	// get payload
	_, err = io.ReadFull(r.Reader, r.buf[:l])
	if err != nil {
		return 0, err
	}

	binary.BigEndian.PutUint16(r.nonce[:2], r.count)
	copy(r.nonce[2:], r.iv[2:12])

	_, err = r.Open(r.buf[:0], r.nonce[:r.NonceSize()], r.buf[:l], nil)
	r.count++
	if err != nil {
		return 0, err
	}

	r.dataLen = int(l) - r.Overhead()
	m := copy(b, r.buf[:r.dataLen])
	if m < int(r.dataLen) {
		r.offset = m
	} else {
		r.offset = r.dataLen
		utils.PutBytes(r.buf)
		r.buf = nil
	}

	return m, err
}
