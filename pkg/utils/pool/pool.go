package pool

import (
	"encoding/binary"
	"io"
	"math"
	"math/bits"
	"net"
	"net/http/httputil"
	"sync"
)

const MaxSegmentSize = math.MaxUint16
const DefaultSize = 16 * 0x400

// MaxLength is the maximum length of an element that can be added to the Pool.
const MaxLength = math.MaxInt32

type Pool interface {
	GetBytes(size int) []byte
	PutBytes(b []byte)
}

var DefaultPool Pool = &pool{}

func GetBytes[T Integer](size T) []byte { return DefaultPool.GetBytes(int(size)) }
func PutBytes(b []byte)                 { DefaultPool.PutBytes(b) }

func Clone(b []byte) []byte {
	v := GetBytes(len(b))
	copy(v, b)
	return v
}

var _ httputil.BufferPool = (*ReverseProxyBuffer)(nil)

type ReverseProxyBuffer struct{}

func (ReverseProxyBuffer) Get() []byte  { return GetBytes(DefaultSize) }
func (ReverseProxyBuffer) Put(b []byte) { PutBytes(b) }

var buffers [32]*sync.Pool

func init() {
	for i := range buffers {
		buffers[i] = &sync.Pool{
			New: func() any { return make([]byte, 1<<i) },
		}
	}
}

// Log of base two, round up (for v > 0).
func nextLogBase2(v uint32) uint32 {
	return uint32(bits.Len32(v - 1))
}

// Log of base two, round down (for v > 0)
func prevLogBase2(num uint32) uint32 {
	next := nextLogBase2(num)
	if num == (1 << uint32(next)) {
		return next
	}
	return next - 1
}

type pool struct{}

func (pool) GetBytes(size int) []byte {
	if size == 0 {
		return nil
	}

	// Calling this function with a negative length is invalid.
	// make will panic if length is negative, so we don't have to.
	if size > MaxLength || size < 0 {
		return make([]byte, size)
	}

	l := nextLogBase2(uint32(size))
	b := buffers[l].Get().([]byte)[:size]

	// debug.Get(b)

	return b
}

func (pool) PutBytes(b []byte) {
	if cap(b) > MaxLength || cap(b) <= 0 {
		return
	}

	// debug.Put(b)

	l := prevLogBase2(uint32(cap(b)))
	buffers[l].Put(b) //lint:ignore SA6002 ignore temporarily
}

// var debug = &Deubg{}

// type Deubg struct {
// 	store syncmap.SyncMap[string, struct {
// 		value bool
// 		last  string
// 	}]
// }

// func (d *Deubg) Get(b []byte) {
// 	d.store.Store(fmt.Sprintf("%p", b), struct {
// 		value bool
// 		last  string
// 	}{})
// }

// func (d *Deubg) Put(b []byte) {
// 	ptr := fmt.Sprintf("%p", b)
// 	if z, _ := d.store.Load(ptr); z.value {
// 		log.Error("double free", "ptr", ptr, "caller", fmt.Sprint(runtime.Caller(2)), "last", z.last)
// 	}
// 	d.store.Store(fmt.Sprintf("%p", b), struct {
// 		value bool
// 		last  string
// 	}{
// 		value: true,
// 		last:  fmt.Sprint(runtime.Caller(2)),
// 	})
// }

type BytesReader struct {
	index int
	b     []byte
	mu    sync.Mutex
}

func NewBytesReader(b []byte) *BytesReader {
	return &BytesReader{
		index: 0,
		b:     b,
	}
}

func (r *BytesReader) Read(b []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.b == nil || r.index >= len(r.b) {
		if r.b != nil {
			PutBytes(r.b)
			r.b = nil
		}
		return 0, io.EOF
	}

	n := copy(b, r.b[r.index:])
	r.index += n

	return n, nil
}

type multipleReaderTCPConn struct {
	*net.TCPConn
	mr io.Reader
}

func (m *multipleReaderTCPConn) Read(b []byte) (int, error) {
	return m.mr.Read(b)
}

type multipleReaderConn struct {
	net.Conn
	mr io.Reader
}

func newMultipleReaderConn(c net.Conn, r io.Reader) net.Conn {
	tc, ok := c.(*net.TCPConn)
	if ok {
		return &multipleReaderTCPConn{tc, r}
	}

	return &multipleReaderConn{c, r}
}

func (m *multipleReaderConn) Read(b []byte) (int, error) {
	return m.mr.Read(b)
}

func NewBytesConn(c net.Conn, bytes []byte) net.Conn {
	if len(bytes) == 0 {
		return c
	}

	return newMultipleReaderConn(c, io.MultiReader(NewBytesReader(bytes), c))
}

func BinaryWriteUint16(w io.Writer, order binary.ByteOrder, v uint16) error {
	buf := GetBytes(2)
	defer PutBytes(buf)

	order.PutUint16(buf, v)

	_, err := w.Write(buf)
	return err
}

func BinaryWriteUint64(w io.Writer, order binary.ByteOrder, v uint64) error {
	buf := GetBytes(8)
	defer PutBytes(buf)

	order.PutUint64(buf, v)

	_, err := w.Write(buf)
	return err
}

type Integer interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 | ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr
}
