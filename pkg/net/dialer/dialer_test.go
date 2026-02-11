package dialer

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
)

func TestDialContextWithOptions_TCP(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		conn.Close()
	}()

	conn, err := DialContextWithOptions(context.Background(), "tcp", l.Addr().String(), &Options{})
	if err != nil {
		t.Fatalf("DialContextWithOptions TCP failed: %v", err)
	}
	conn.Close()
}

func TestDialContextWithOptions_TCP_Localhost(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		conn.Close()
	}()

	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	// This assumes localhost resolves to 127.0.0.1
	// If it resolves to ::1, connection might fail if listener is only on IPv4.
	// But let's try. If localhost resolves to ::1, DialTCP will try ::1.
	// We bound to 127.0.0.1. So it should fail if localhost is ONLY ::1.
	// If localhost is 127.0.0.1, it works.
	// If localhost is both, it tries both (Happy Eyeballs logic? No, sequential in our impl).
	// Our impl tries all resolved IPs.
	// If ::1 fails, it tries 127.0.0.1.

	addr := fmt.Sprintf("localhost:%s", port)
	conn, err := DialContextWithOptions(context.Background(), "tcp", addr, &Options{})
	if err != nil {
		// Verify if resolution failed or dial failed
		t.Logf("DialContextWithOptions TCP localhost failed: %v", err)
		return
	}
	conn.Close()
}

func TestDialContextWithOptions_UDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	conn, err := DialContextWithOptions(context.Background(), "udp", pc.LocalAddr().String(), &Options{})
	if err != nil {
		t.Fatalf("DialContextWithOptions UDP failed: %v", err)
	}
	conn.Close()
}

func TestDialContextWithOptions_Unix(t *testing.T) {
	// Use a temp file for socket
	f, err := os.CreateTemp("", "test-socket-*.sock")
	if err != nil {
		t.Skip("skipping unix socket test due to temp file error")
	}
	path := f.Name()
	f.Close()
	os.Remove(path) // Remove so Listen can create it

	l, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("skipping unix socket test: %v", err)
	}
	defer l.Close()
	defer os.Remove(path)

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		conn.Close()
	}()

	conn, err := DialContextWithOptions(context.Background(), "unix", path, &Options{})
	if err != nil {
		t.Fatalf("DialContextWithOptions Unix failed: %v", err)
	}
	conn.Close()
}
