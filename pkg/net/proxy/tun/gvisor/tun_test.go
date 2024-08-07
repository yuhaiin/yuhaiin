package gvisor

import (
	"net"
	"testing"
)

func TestInterfaces(t *testing.T) {
	z := make([][]byte, 100)
	z = z[:0]

	z = append(z, []byte("ddd"))

	t.Log(z)

	i := 0
	for ; i < 10; i++ {
		t.Log(i)
	}

	is, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}

	t.Log(is)

	for _, i := range is {
		t.Log(i.Name)
	}
}
