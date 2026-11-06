package pool

import (
	"bytes"
	"io"
	"net"
	"testing"
)

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	l, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan *net.TCPConn, 1)
	go func() {
		c, _ := l.AcceptTCP()
		done <- c
	}()
	client, err := net.DialTCP("tcp4", nil, l.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	server := <-done
	if server == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	return client, server
}

func TestBytesConnWriteToKeepsPrefix(t *testing.T) {
	client, server := tcpPair(t)
	go func() {
		_, _ = server.Write([]byte("tail"))
		_ = server.CloseWrite()
	}()
	conn := NewBytesConn(client, []byte("head-"))
	var out bytes.Buffer
	// io.Copy prefers WriterTo; a promoted (*net.TCPConn).WriteTo skips the prefix.
	if _, err := io.Copy(&out, conn); err != nil {
		t.Fatal(err)
	}
	if out.String() != "head-tail" {
		t.Fatalf("got %q", out.String())
	}
}

type wrappedTCP struct{ *net.TCPConn }

func TestBytesConnKeepsHalfCloseForWrappers(t *testing.T) {
	client, _ := tcpPair(t)
	conn := NewBytesConn(wrappedTCP{client}, []byte("x"))
	if _, ok := conn.(interface{ CloseWrite() error }); !ok {
		t.Fatal("wrapped TCP connection lost CloseWrite")
	}
}
