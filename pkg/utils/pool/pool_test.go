package pool

import (
	"fmt"
	"io"
	"net"
	"os"
	"testing"
)

func TestBytes(t *testing.T) {
	b := GetBytes(1111)
	t.Log(len(b), cap(b), fmt.Sprintf("%p", b))

	v := nextLogBase2(1111)

	t.Log(v, prevLogBase2(2048))

	PutBytes(b)
	PutBytes(b)
}

func TestBytesReader(t *testing.T) {
	b := GetBytes(11)

	copy(b, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10})

	r := &BytesReader{b: b}

	buf := make([]byte, 5)
	for {
		n, err := r.Read(buf)
		if err != nil {
			break
		}
		t.Log(buf[:n])
	}

	t.Log(r.Read(buf))
}

func TestPrefixConn(t *testing.T) {
	conn1, _ := net.Pipe()
	conn1.Close()

	x := NewBytesConn(conn1, []byte("abc"))
	defer x.Close()

	_, _ = io.Copy(os.Stdout, x)
}
