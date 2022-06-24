package tun

import (
	"net"
	"testing"
)

func TestInterfaces(t *testing.T) {
	is, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}

	t.Log(is)

	for _, i := range is {
		t.Log(i.Name)
	}
}
