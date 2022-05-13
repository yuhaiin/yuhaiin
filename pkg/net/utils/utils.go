package utils

import (
	"bytes"
	"errors"
	"io"
	"log"
	"math/bits"
	"net"
	"sync"
	"time"
)

type Pool interface {
	GetBytes(size int) []byte
	PutBytes(b []byte)

	GetBuffer() *bytes.Buffer
	PutBuffer(b *bytes.Buffer)
}

var DefaultSize = 16 * 0x400
var DefaultPool Pool = &pool{}

func GetBytes(size int) []byte  { return DefaultPool.GetBytes(size) }
func PutBytes(b []byte)         { DefaultPool.PutBytes(b) }
func GetBuffer() *bytes.Buffer  { return DefaultPool.GetBuffer() }
func PutBuffer(b *bytes.Buffer) { DefaultPool.PutBuffer(b) }

var poolMap = sync.Map{}

type pool struct{}

func buffPool(size int) *sync.Pool {
	if v, ok := poolMap.Load(size); ok {
		return v.(*sync.Pool)
	}

	p := &sync.Pool{
		New: func() any {
			return make([]byte, size)
		},
	}
	poolMap.Store(size, p)
	return p
}

func (pool) GetBytes(size int) []byte {
	l := bits.Len(uint(size)) - 1
	if size != 1<<l {
		size = 1 << (l + 1)
	}
	return buffPool(size).Get().([]byte)
}

func (pool) PutBytes(b []byte) {
	l := bits.Len(uint(len(b))) - 1
	buffPool(1 << l).Put(b) //lint:ignore SA6002 ignore temporarily
}

var bufpool = sync.Pool{New: func() any { return bytes.NewBuffer(nil) }}

func (pool) GetBuffer() *bytes.Buffer { return bufpool.Get().(*bytes.Buffer) }
func (pool) PutBuffer(b *bytes.Buffer) {
	b.Reset()
	bufpool.Put(b)
}

//Relay pipe
func Relay(local, remote io.ReadWriter) {
	wait := make(chan struct{})
	go func() {
		defer close(wait)
		if err := Copy(remote, local); err != nil && !errors.Is(err, io.EOF) {
			if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
				log.Println("replay local -> remote failed:", err)
			}
		}
		if r, ok := remote.(net.Conn); ok {
			r.SetReadDeadline(time.Now()) // make another Copy exit
		}
	}()

	if err := Copy(local, remote); err != nil && !errors.Is(err, io.EOF) {
		if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
			log.Println("relay remote -> local failed:", err)
		}
	}
	if r, ok := local.(net.Conn); ok {
		r.SetReadDeadline(time.Now())
	}

	<-wait
}

func Copy(dst io.Writer, src io.Reader) (err error) {
	if c, ok := dst.(io.ReaderFrom); ok {
		_, err = c.ReadFrom(src) // local -> remote
	} else if c, ok := src.(io.WriterTo); ok {
		_, err = c.WriteTo(dst) // local -> remote
	} else {
		buf := GetBytes(DefaultSize)
		defer PutBytes(buf)
		_, err = io.CopyBuffer(dst, src, buf) // local -> remote
	}

	return
}

//Unit .
type Unit int

var (
	//B .
	B Unit = 0
	//KB .
	KB Unit = 1
	//MB .
	MB Unit = 2
	//GB .
	GB Unit = 3
	//TB .
	TB Unit = 4
	//PB .
	PB Unit = 5
)

func (u Unit) String() string {
	switch u {
	case B:
		return "B"
	case KB:
		return "KB"
	case MB:
		return "MB"
	case GB:
		return "GB"
	case TB:
		return "TB"
	case PB:
		return "PB"
	default:
		return "B"
	}
}

//ReducedUnit .
func ReducedUnit(byte float64) (result float64, unit Unit) {
	if byte > 1125899906842624 {
		return byte / 1125899906842624, PB //PB
	}
	if byte > 1099511627776 {
		return byte / 1099511627776, TB //TB
	}
	if byte > 1073741824 {
		return byte / 1073741824, GB //GB
	}
	if byte > 1048576 {
		return byte / 1048576, MB //MB
	}
	if byte > 1024 {
		return byte / 1024, KB //KB
	}
	return byte, B //B
}
