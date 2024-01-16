package pool

import (
	"bytes"
	"math/bits"
	"net/http/httputil"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"golang.org/x/exp/constraints"
)

var MaxSegmentSize = (1 << 16) - 1

type Pool interface {
	GetBytes(size int) []byte
	PutBytes(b []byte)

	GetBuffer() *bytes.Buffer
	PutBuffer(b *bytes.Buffer)
}

const DefaultSize = 20 * 0x400

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

type MultipleBytes []*Bytes

func (m MultipleBytes) Drop() {
	for _, v := range m {
		PutBytesBuffer(v)
	}
}

type Bytes struct {
	once  sync.Once
	buf   []byte
	start int
	end   int
}

func (b *Bytes) Bytes() []byte          { return b.buf[b.start:b.end] }
func (b *Bytes) After(index int) []byte { return b.buf[b.start+index : b.end] }
func (b *Bytes) ResetSize(start, end int) {
	if end <= len(b.buf) {
		b.end = end
	}

	if start >= 0 && start <= end {
		b.start = start
	}
}

func (b *Bytes) Len() int { return b.end - b.start }

func NewBytesBuffer(b []byte) *Bytes { return &Bytes{sync.Once{}, b, 0, len(b)} }

func GetBytesBuffer[T constraints.Integer](size T) *Bytes {
	realSize := int(size)
	if realSize < DefaultSize {
		realSize = DefaultSize
	}

	return &Bytes{sync.Once{}, GetBytes(realSize), 0, int(size)}
}
func PutBytesBuffer(b *Bytes) { b.once.Do(func() { PutBytes(b.buf) }) }
