package resolver

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/relay"
)

func fakeIPTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	server, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	for _, conn := range []*net.TCPConn{client, server} {
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	return client, server
}

func TestLeasedFakeIPConnPreservesResponseAfterClientFIN(t *testing.T) {
	client, inbound := fakeIPTCPPair(t)
	outbound, server := fakeIPTCPPair(t)
	var released atomic.Int32
	conn := &leasedFakeIPConn{Conn: outbound, release: sync.OnceFunc(func() { released.Add(1) })}
	t.Cleanup(func() { _ = conn.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		relay.Relay(inbound, conn)
	}()

	if _, err := io.WriteString(client, "request"); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	request, err := io.ReadAll(server)
	if err != nil || string(request) != "request" {
		t.Fatalf("server request = %q, error = %v", request, err)
	}
	if released.Load() != 0 {
		t.Fatal("client FIN released the mapping while the response was pending")
	}
	if _, err := io.WriteString(server, "response after EOF"); err != nil {
		t.Fatal(err)
	}
	if err := server.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(client)
	if err != nil || string(response) != "response after EOF" {
		t.Fatalf("client response = %q, error = %v", response, err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not finish after both directions reached EOF")
	}
	if released.Load() != 0 {
		t.Fatal("half-closing both directions released the mapping before Close")
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if released.Load() != 1 {
		t.Fatal("Close did not release the mapping")
	}
}

func TestLeasedFakeIPConnCloseWriteWithoutHalfCloseReleasesLease(t *testing.T) {
	local, remote := net.Pipe()
	t.Cleanup(func() { _ = remote.Close() })
	var released bool
	conn := &leasedFakeIPConn{Conn: local, release: func() { released = true }}
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if !released {
		t.Fatal("full-close fallback did not release the mapping")
	}
}
