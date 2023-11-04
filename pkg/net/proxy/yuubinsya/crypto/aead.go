package crypto

import (
	"crypto/cipher"
	"encoding/binary"
	"io"
	"net"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"golang.org/x/crypto/chacha20poly1305"
)

type Aead interface {
	New([]byte) (cipher.AEAD, error)
	KeySize() int
	NonceSize() int
	Name() []byte
}

var Chacha20poly1305 = chacha20poly1305Aead{}

type chacha20poly1305Aead struct{}

func (chacha20poly1305Aead) New(key []byte) (cipher.AEAD, error) { return chacha20poly1305.New(key) }
func (chacha20poly1305Aead) KeySize() int                        { return chacha20poly1305.KeySize }
func (chacha20poly1305Aead) NonceSize() int                      { return chacha20poly1305.NonceSize }
func (chacha20poly1305Aead) Name() []byte                        { return []byte("chacha20poly1305-key") }

type streamConn struct {
	net.Conn
	r io.Reader
	w io.Writer
}

func (c *streamConn) Read(b []byte) (int, error)  { return c.r.Read(b) }
func (c *streamConn) Write(b []byte) (int, error) { return c.w.Write(b) }

// NewConn wraps a stream-oriented net.Conn with cipher.
func NewConn(c net.Conn, rnonce, wnonce []byte, rciph, wciph cipher.AEAD) net.Conn {
	return &streamConn{
		Conn: c,
		r:    NewReader(c, rnonce, rciph, nat.MaxSegmentSize),
		w:    NewWriter(c, wnonce, wciph, nat.MaxSegmentSize),
	}
}

type writer struct {
	io.Writer
	cipher.AEAD
	nonce          []byte
	maxPayloadSize int

	mu sync.Mutex
}

// NewWriter wraps an io.Writer with AEAD encryption.

func NewWriter(w io.Writer, nonce []byte, aead cipher.AEAD, maxPayloadSize int) *writer {
	return &writer{
		Writer:         w,
		AEAD:           aead,
		nonce:          nonce,
		maxPayloadSize: maxPayloadSize,
	}
}

func (w *writer) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return
	}

	buf := pool.GetBytes(2 + w.AEAD.Overhead() + w.maxPayloadSize + w.AEAD.Overhead())
	defer pool.PutBytes(buf)

	for pLen := len(p); pLen > 0; {
		var data []byte
		if pLen > w.maxPayloadSize {
			data = p[:w.maxPayloadSize]
			p = p[w.maxPayloadSize:]
			pLen -= w.maxPayloadSize
		} else {
			data = p
			pLen = 0
		}
		binary.BigEndian.PutUint16(buf[:2], uint16(len(data)))
		w.mu.Lock()
		w.Seal(buf[:0], w.nonce, buf[:2], nil)
		increment(w.nonce)
		offset := w.Overhead() + 2
		packet := w.Seal(buf[offset:offset], w.nonce, data, nil)
		increment(w.nonce)
		_, err = w.Writer.Write(buf[:offset+len(packet)])
		w.mu.Unlock()
		if err != nil {
			return
		}
		n += len(data)
	}

	return
}

type reader struct {
	io.Reader
	cipher.AEAD
	nonce    []byte
	buf      []byte
	leftover []byte

	mu sync.Mutex
}

func NewReader(r io.Reader, nonce []byte, aead cipher.AEAD, maxPayloadSize int) *reader {
	return &reader{
		Reader: r,
		AEAD:   aead,
		buf:    make([]byte, maxPayloadSize+aead.Overhead()),
		nonce:  nonce,
	}
}

// read and decrypt a record into the internal buffer. Return decrypted payload length and any error encountered.
func (r *reader) read() (int, error) {
	// decrypt payload size
	buf := r.buf[:2+r.Overhead()]
	_, err := io.ReadFull(r.Reader, buf)
	if err != nil {
		return 0, err
	}

	_, err = r.Open(buf[:0], r.nonce, buf, nil)
	increment(r.nonce)
	if err != nil {
		return 0, err
	}

	size := int(binary.BigEndian.Uint16(buf[:2]))

	// decrypt payload
	buf = r.buf[:size+r.Overhead()]
	_, err = io.ReadFull(r.Reader, buf)
	if err != nil {
		return 0, err
	}

	_, err = r.Open(buf[:0], r.nonce, buf, nil)
	increment(r.nonce)
	if err != nil {
		return 0, err
	}

	return size, nil
}

// Read reads from the embedded io.Reader, decrypts and writes to b.
func (r *reader) Read(b []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// copy decrypted bytes (if any) from previous record first
	if len(r.leftover) > 0 {
		n := copy(b, r.leftover)
		r.leftover = r.leftover[n:]
		return n, nil
	}

	n, err := r.read()

	m := copy(b, r.buf[:n])
	if m < n { // insufficient len(b), keep leftover for next read
		r.leftover = r.buf[m:n]
	}
	return m, err
}

// increment little-endian encoded unsigned integer b. Wrap around on overflow.
func increment(b []byte) {
	for i := range b {
		b[i]++
		if b[i] != 0 {
			return
		}
	}
}
