package utils

import (
	"fmt"
	"io"
	"sync"
)

var poolMap = sync.Map{}
var DefaultSize = 8 * 0x400

func buffPool(size int) *sync.Pool {
	if v, ok := poolMap.Load(size); ok {
		return v.(*sync.Pool)
	}

	p := &sync.Pool{
		New: func() interface{} {
			x := make([]byte, size)
			return &x
		},
	}
	poolMap.Store(size, p)
	return p
}

func GetBytes(size int) []byte {
	return *buffPool(size).Get().(*[]byte)
}

func PutBytes(size int, b *[]byte) {
	buffPool(size).Put(b)
}

//Forward pipe
func Forward(conn1, conn2 io.ReadWriter) {
	buf := GetBytes(DefaultSize)
	defer PutBytes(DefaultSize, &buf)
	i := DefaultSize / 2

	go func() {
		_, _ = io.CopyBuffer(conn2, conn1, buf[:i])
	}()
	_, _ = io.CopyBuffer(conn1, conn2, buf[i:])
}

//SingleForward single pipe
func SingleForward(src io.Reader, dst io.Writer) (err error) {
	buf := GetBytes(DefaultSize)
	defer PutBytes(DefaultSize, &buf)
	_, err = io.CopyBuffer(dst, src, buf)
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
