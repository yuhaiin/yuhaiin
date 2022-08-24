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
	buf   [lenSize + maxChunkSize]byte
	count uint16
	iv    []byte
}

// AEADWriter returns a aead writer
func AEADWriter(w io.Writer, aead cipher.AEAD, iv []byte) writer {
	return &aeadWriter{
		Writer: w,
		AEAD:   aead,
		nonce:  make([]byte, aead.NonceSize()),
		count:  0,
		iv:     iv,
	}
}

func (w *aeadWriter) Close() error { return nil }

func (w *aeadWriter) Write(b []byte) (int, error) {
	n, err := w.ReadFrom(bytes.NewBuffer(b))
	return int(n), err
}

func (w *aeadWriter) ReadFrom(r io.Reader) (n int64, err error) {
	buf := w.buf[:]
	for {
		payloadBuf := w.buf[lenSize : lenSize+defaultChunkSize-w.Overhead()]

		nr, er := r.Read(payloadBuf)
		if nr > 0 {
			n += int64(nr)
			buf = buf[:lenSize+nr+w.Overhead()]
			payloadBuf = payloadBuf[:nr]
			binary.BigEndian.PutUint16(w.buf[:lenSize], uint16(nr+w.Overhead()))

			binary.BigEndian.PutUint16(w.nonce[:2], w.count)
			copy(w.nonce[2:], w.iv[2:12])

			w.Seal(payloadBuf[:0], w.nonce[:w.NonceSize()], payloadBuf, nil)
			w.count++

			_, ew := w.Writer.Write(buf)
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
	count uint16
	iv    []byte

	decrypted bytes.Buffer
}

// AEADReader returns a aead reader
func AEADReader(r io.Reader, aead cipher.AEAD, iv []byte) io.ReadCloser {
	return &aeadReader{
		Reader: r,
		AEAD:   aead,
		count:  0,
		iv:     iv,
	}
}

func (r *aeadReader) Close() error { return nil }

func (r *aeadReader) Read(b []byte) (int, error) {
	if r.decrypted.Len() > 0 {
		return r.decrypted.Read(b)
	}

	lb := utils.GetBytes(r.NonceSize())
	defer utils.PutBytes(lb)

	// get length
	_, err := io.ReadFull(r.Reader, lb[:lenSize])
	if err != nil {
		return 0, err
	}

	// if length == 0, then this is the end
	l := binary.BigEndian.Uint16(lb[:lenSize])
	if l == 0 {
		return 0, nil
	}

	buf := utils.GetBytes(int(l))
	defer utils.PutBytes(buf)
	// get payload
	_, err = io.ReadFull(r.Reader, buf[:l])
	if err != nil {
		return 0, err
	}

	binary.BigEndian.PutUint16(lb[:2], r.count)
	copy(lb[2:], r.iv[2:12])

	_, err = r.Open(buf[:0], lb[:r.NonceSize()], buf[:l], nil)
	r.count++
	if err != nil {
		return 0, err
	}

	r.decrypted.Write(buf[:int(l)-r.Overhead()])
	return r.decrypted.Read(b)
}
