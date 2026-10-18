package ssh

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

func TestChannelDeadlineRecoveryAndIsolation(t *testing.T) {
	addr, pin, accepted := startSSHServer(t)
	p := newTestClient(t, addr, pin)
	first, err := p.Conn(t.Context(), testTarget(t))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := p.Conn(t.Context(), testTarget(t))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := first.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read = %v", err)
	}
	if err := first.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	for _, conn := range []net.Conn{first, second} {
		if _, err := conn.Write([]byte("alive")); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, 5)
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatal(err)
		}
		if string(got) != "alive" {
			t.Fatalf("echo = %q", got)
		}
	}
	if got := accepted.Load(); got != 1 {
		t.Fatalf("transport count = %d", got)
	}
}

func TestChannelWriteDeadlineRecovery(t *testing.T) {
	raw, peer := net.Pipe()
	defer peer.Close()
	conn := wrapChannel(raw)
	defer conn.Close()
	if err := conn.SetWriteDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	n, err := conn.Write(bytes.Repeat([]byte("x"), 1024*1024))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("write = %d, %v", n, err)
	}
	if n >= 1024*1024 {
		t.Fatalf("timed-out write accepted the entire buffer")
	}
	if err := conn.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	finished := make(chan struct{})
	go func() { defer close(finished); _, _ = io.Copy(io.Discard, peer) }()
	if _, err := conn.Write([]byte("recovered")); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	<-finished
}

func TestChannelCloseWriteDrainsPayload(t *testing.T) {
	addr, pin, _ := startSSHServer(t)
	p := newTestClient(t, addr, pin)
	conn, err := p.Conn(t.Context(), testTarget(t))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload := bytes.Repeat([]byte("last bytes"), 10000)
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload length = %d, want %d", len(got), len(payload))
	}
}
