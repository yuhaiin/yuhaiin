package utils

import (
	"fmt"
	"io"
	"math/bits"
	"net"
	"sync"
	"time"
)

var poolMap = sync.Map{}
var DefaultSize = 8 * 0x400

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

//Relay pipe
func Relay(local, remote io.ReadWriter) {
	wait := make(chan struct{})
	go func() {
		defer close(wait)
		Copy(remote, local)
		if r, ok := remote.(net.Conn); ok {
			r.SetReadDeadline(time.Now())
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
	//B2 .
	B2 = "B"
	//KB2 .
	KB2 = "KB"
	//MB2 .
	MB2 = "MB"
	//GB2 .
	GB2 = "GB"
	//TB2 .
	TB2 = "TB"
	//PB2 .
	PB2 = "PB"
)

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

//ReducedUnitStr .
func ReducedUnitStr(byte float64) (result string) {
	if byte > 1125899906842624 {
		return fmt.Sprintf("%.2f%s", byte/1125899906842624, PB2) //PB
	}
	if byte > 1099511627776 {
		return fmt.Sprintf("%.2f%s", byte/1099511627776, TB2) //TB
	}
	if byte > 1073741824 {
		return fmt.Sprintf("%.2f%s", byte/1073741824, GB2) //GB
	}
	if byte > 1048576 {
		return fmt.Sprintf("%.2f%s", byte/1048576, MB2) //MB
	}
	if byte > 1024 {
		return fmt.Sprintf("%.2f%s", byte/1024, KB2) //KB
	}
	return fmt.Sprintf("%.2f%s", byte, B2) //B
}
