package netapi

import (
	"net"
	"syscall"
	"testing"

	"golang.org/x/net/nettest"
)

func TestServer(t *testing.T) {
	lis, err := nettest.NewLocalListener("tcp")
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close()

	ii := NewListener(lis.(*net.TCPListener), nil)

	lri, ok := lis.(syscall.Conn)
	t.Log(lri, ok)
	ri, ok := ii.(syscall.Conn)
	t.Log(ri, ok)
	if ok {
		t.Log(ri.SyscallConn())
	}
}
