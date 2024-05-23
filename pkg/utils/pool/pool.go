package pool

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"
	"math/bits"
	"net"
	"net/http/httputil"
	"sync"
	"unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"golang.org/x/exp/constraints"
)

var MaxSegmentSize = math.MaxUint16

type Pool interface {
	GetBytes(size int) []byte
	PutBytes(b []byte)

	GetBuffer() *bytes.Buffer
	PutBuffer(b *bytes.Buffer)
}

const DefaultSize = 16 * 0x400

var DefaultPool Pool = &pool{}

func GetBytes[T constraints.Integer](size T) []byte { return DefaultPool.GetBytes(int(size)) }
func PutBytes(b []byte)                             { DefaultPool.PutBytes(b) }
func GetBuffer() *bytes.Buffer                      { return DefaultPool.GetBuffer() }
func PutBuffer(b *bytes.Buffer)                     { DefaultPool.PutBuffer(b) }

var _ httputil.BufferPool = (*ReverseProxyBuffer)(nil)

type ReverseProxyBuffer struct{}

func (ReverseProxyBuffer) Get() []byte  { return GetBytes(DefaultSize) }
func (ReverseProxyBuffer) Put(b []byte) { PutBytes(b) }

var poolMap syncmap.SyncMap[int, *sync.Pool]

type pool struct{}

func buffPool(size int) *sync.Pool {
	if v, ok := poolMap.Load(size); ok {
		return v
	}

	p := &sync.Pool{New: func() any { return make([]byte, size) }}
	poolMap.Store(size, p)
	return p
}

func (pool) GetBytes(size int) []byte {
	if size == 0 {
		return nil
	}

	l := bits.Len(uint(size)) - 1
	if size != 1<<l {
		size = 1 << (l + 1)
	}
	return buffPool(size).Get().([]byte)
}

func (pool) PutBytes(b []byte) {
	if len(b) == 0 {
		return
	}

	l := bits.Len(uint(len(b))) - 1
	buffPool(1 << l).Put(b) //lint:ignore SA6002 ignore temporarily
}

var bufpool = sync.Pool{New: func() any {
	buffer := bytes.NewBuffer(make([]byte, DefaultSize))
	buffer.Reset()
	return buffer
}}

func (pool) GetBuffer() *bytes.Buffer { return bufpool.Get().(*bytes.Buffer) }
func (pool) PutBuffer(b *bytes.Buffer) {
	if b != nil {
		b.Reset()
		bufpool.Put(b)
	}
}

type MultipleBuffer []*Buffer

func (m MultipleBuffer) Free() {
	for _, v := range m {
		v.Free()
	}
}

type MultipleBytes []*Bytes

func (m MultipleBytes) Free() {
	for _, v := range m {
		v.Free()
	}
}

type Bytes struct {
	once  sync.Once
	buf   []byte
	start int
	end   int
}

func (b *Bytes) Bytes() []byte          { return b.buf[b.start:b.end] }
func (b *Bytes) String() string         { return string(b.Bytes()) }
func (b *Bytes) After(index int) []byte { return b.buf[b.start+index : b.end] }
func (b *Bytes) Refactor(start, end int) *Bytes {
	if end <= len(b.buf) {
		b.end = end
	}

	if start >= 0 && start <= end {
		b.start = start
	}

	return b
}

func (b *Bytes) Reset() {
	b.start = 0
	b.end = len(b.buf)
}

func (b *Bytes) Copy(byte []byte) *Bytes {
	b.end = b.start + copy(b.Bytes(), byte)
	return b
}

func (b *Bytes) Len() int { return b.end - b.start }

func (b *Bytes) ReadFrom(c io.Reader) (int64, error) {
	n, err := c.Read(b.Bytes())
	if err != nil {
		return int64(n), err
	}

	b.end = n

	return int64(n), err
}

func (b *Bytes) ReadFull(c io.Reader) (int64, error) {
	n, err := io.ReadFull(c, b.Bytes())
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		err = nil
	}

	return int64(n), err
}

func (b *Bytes) AsWriter() *Buffer {
	b.start = 0
	b.end = 0

	return &Buffer{b}
}

func (b *Bytes) ReadFromPacket(pc net.PacketConn) (int, net.Addr, error) {
	n, addr, err := pc.ReadFrom(b.Bytes())
	if err != nil {
		return n, addr, err
	}

	b.end = n

	return n, addr, err
}

func (b *Bytes) Free() {
	putBytesBuffer(b)
}

func NewBytesBuffer(b []byte) *Bytes { return &Bytes{sync.Once{}, b, 0, len(b)} }

func GetBytesBuffer[T constraints.Integer](size T) *Bytes {
	return &Bytes{sync.Once{},
		GetBytes(size), 0, int(size)}
}

func putBytesBuffer(b *Bytes) { b.once.Do(func() { PutBytes(b.buf) }) }

func GetBytesWriter[T constraints.Integer](size T) *Buffer {
	b := &Bytes{sync.Once{},
		GetBytes(size), 0, 0}
	return &Buffer{b}
}

type Buffer struct {
	b *Bytes
}

func NewBuffer(b []byte) *Buffer { return &Buffer{NewBytesBuffer(b)} }

func (b *Buffer) freeSlice() []byte {
	return b.b.buf[b.b.end:]
}

func (b *Buffer) WriteUint16(v uint16) {
	if len(b.freeSlice()) < 2 {
		return
	}

	binary.BigEndian.PutUint16(b.freeSlice(), v)
	b.b.end += 2
}

func (b *Buffer) WriteLittleEndianUint16(v uint16) {
	if len(b.freeSlice()) < 2 {
		return
	}

	binary.LittleEndian.PutUint16(b.freeSlice(), v)
	b.b.end += 2
}

func (b *Buffer) WriteUint32(v uint32) {
	if len(b.freeSlice()) < 4 {
		return
	}

	binary.BigEndian.PutUint32(b.freeSlice(), v)
	b.b.end += 4
}
func (b *Buffer) WriteLittleEndianUint32(v uint32) {
	if len(b.freeSlice()) < 4 {
		return
	}

	binary.LittleEndian.PutUint32(b.freeSlice(), v)
	b.b.end += 4
}

func (b *Buffer) WriteUint64(v uint64) {
	if len(b.freeSlice()) < 8 {
		return
	}

	binary.BigEndian.PutUint64(b.freeSlice(), v)
	b.b.end += 8
}

func (b *Buffer) WriteLittleEndianUint64(v uint64) {
	if len(b.freeSlice()) < 8 {
		return
	}

	binary.LittleEndian.PutUint64(b.freeSlice(), v)
	b.b.end += 8
}

func (b *Buffer) Write(bb []byte) (int, error) {
	n := copy(b.freeSlice(), bb)
	b.b.end += n
	return n, nil
}

func (b *Buffer) Advance(i int) {
	if i <= 0 {
		return
	}
	free := len(b.freeSlice())
	if free < i {
		b.b.end += free
	} else {
		b.b.end += i
	}
}

func (b *Buffer) Retreat(i int) {
	if i <= 0 {
		return
	}

	if b.b.end < i {
		b.b.end = 0
	} else {
		b.b.end -= i
	}
}

func (b *Buffer) WriteString(s string) {
	_, _ = b.Write(unsafe.Slice(unsafe.StringData(s), len(s)))
}

func (b *Buffer) WriteByte(v byte) error {
	_, err := b.Write([]byte{v})
	return err
}

func (b *Buffer) ReadFrom(c io.Reader) (int64, error) {
	return b.b.ReadFrom(c)
}

func (b *Buffer) ReadFromPacket(pc net.PacketConn) (int, net.Addr, error) {
	return b.b.ReadFromPacket(pc)
}

func (b *Buffer) Len() int      { return b.b.Len() }
func (b *Buffer) Bytes() []byte { return b.b.Bytes() }

func (b *Buffer) String() string { return b.b.String() }

func (b *Buffer) Truncate(n int) {
	if n <= 0 {
		b.b.start = 0
		b.b.end = 0
		return
	}

	if n >= b.b.end {
		return
	}

	b.b.end = n
}

func (b *Buffer) Discard(n int) []byte {
	if n > b.b.end-b.b.start {
		x := b.Bytes()
		b.b.start = b.b.end
		return x
	}

	x := b.b.buf[b.b.start : b.b.start+n]
	b.b.start += n
	return x
}

func (b *Buffer) Unwrap() *Bytes { return b.b }

func (b *Buffer) Free() {
	putBytesBuffer(b.b)
}
