package utils

import (
	"bytes"
	"io"
	"math/bits"
	"net"
	"sync"
	"time"
)

var poolMap = sync.Map{}
var DefaultSize = 16 * 0x400

func buffPool(size int) *sync.Pool {

	if v, ok := poolMap.Load(size); ok {
		return v.(*sync.Pool)
	}

	p := &sync.Pool{
		New: func() interface{} {
			return make([]byte, size)
		},
	}
	poolMap.Store(size, p)
	return p
}

func GetBytes(size int) []byte {
	l := bits.Len(uint(size)) - 1
	if size != 1<<l {
		size = 1 << (l + 1)
	}
	return buffPool(size).Get().([]byte)
}

func PutBytes(b []byte) {
	l := bits.Len(uint(len(b))) - 1
	buffPool(1 << l).Put(b) //lint:ignore SA6002 ignore temporarily
}

var bufpool = sync.Pool{
	New: func() any { return bytes.NewBuffer(nil) },
}

func GetBuffer() *bytes.Buffer {
	return bufpool.Get().(*bytes.Buffer)
}

func PutBuffer(b *bytes.Buffer) {
	b.Reset()
	bufpool.Put(b)
}

//Relay pipe
func Relay(local, remote io.ReadWriter) {
	wait := make(chan struct{})
	go func() {
		defer close(wait)
		Copy(remote, local)
		if r, ok := remote.(net.Conn); ok {
			r.SetReadDeadline(time.Now()) // make another Copy exit
		}
	}()

	Copy(local, remote)
	if r, ok := local.(net.Conn); ok {
		r.SetReadDeadline(time.Now())
	}

	<-wait
}

func Copy(dst io.Writer, src io.Reader) (err error) {
	if c, ok := dst.(io.ReaderFrom); ok {
		c.ReadFrom(src) // local -> remote
	} else if c, ok := src.(io.WriterTo); ok {
		c.WriteTo(dst) // local -> remote
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
