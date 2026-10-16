package lightweight

import (
	"bytes"
	"context"
	"errors"
	"go.uber.org/goleak"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type memoryIO struct {
	rx, tx chan []byte
	done   chan struct{}
	once   sync.Once
}

func memoryPair() (*memoryIO, *memoryIO) {
	a, b := make(chan []byte, 1024), make(chan []byte, 1024)
	return &memoryIO{rx: a, tx: b, done: make(chan struct{})}, &memoryIO{rx: b, tx: a, done: make(chan struct{})}
}
func (m *memoryIO) ReadPacket(b []byte) (int, error) {
	select {
	case <-m.done:
		return 0, net.ErrClosed
	case p := <-m.rx:
		if len(p) > len(b) {
			return 0, io.ErrShortBuffer
		}
		return copy(b, p), nil
	}
}
func (m *memoryIO) WritePacket(b []byte) error {
	select {
	case <-m.done:
		return net.ErrClosed
	case m.tx <- bytes.Clone(b):
		return nil
	}
}
func (m *memoryIO) Close() error { m.once.Do(func() { close(m.done) }); return nil }

func stackPair(t testing.TB, mtus ...int) (*Stack, *Stack) {
	mtu := 1500
	if len(mtus) > 0 {
		mtu = mtus[0]
	}
	t.Helper()
	return stackPairConfig(t, Config{MTU: mtu})
}
func stackPairConfig(t testing.TB, cfg Config) (*Stack, *Stack) {
	t.Helper()
	a, b := memoryPair()
	cfg.Addresses = []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")}
	x, err := New(cfg, a)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Addresses = []netip.Addr{netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("2001:db8::2")}
	y, err := New(cfg, b)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = x.Close(); _ = y.Close() })
	return x, y
}

func TestUDPSockets(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	a, b := stackPair(t)
	for _, addr := range []string{"192.0.2.2:9000", "[2001:db8::2]:9000"} {
		dst := netip.MustParseAddrPort(addr)
		server, err := b.ListenUDP(dst)
		if err != nil {
			t.Fatal(err)
		}
		client, err := a.DialUDP(netip.AddrPort{}, dst)
		if err != nil {
			t.Fatal(err)
		}
		_ = server.SetDeadline(time.Now().Add(time.Second))
		_ = client.SetDeadline(time.Now().Add(time.Second))
		if _, err = client.Write([]byte("hello")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 64)
		n, from, err := server.ReadFrom(buf)
		if err != nil || string(buf[:n]) != "hello" {
			t.Fatalf("read %q %v", buf[:n], err)
		}
		if _, err = server.WriteTo(buf[:n], from); err != nil {
			t.Fatal(err)
		}
		n, err = client.Read(buf)
		if err != nil || string(buf[:n]) != "hello" {
			t.Fatalf("reply %q %v", buf[:n], err)
		}
		_ = client.Close()
		_ = server.Close()
	}
	_ = a.Close()
	_ = b.Close()
	if a.Stats().MemoryBytes != 0 || b.Stats().MemoryBytes != 0 {
		t.Fatal("memory retained after close")
	}
}

func TestInvalidConfigAndIOClose(t *testing.T) {
	m, _ := memoryPair()
	if _, err := New(Config{CongestionControl: "missing"}, m); err == nil {
		t.Fatal("accepted missing algorithm")
	}
	s, err := New(Config{}, m)
	if err != nil {
		t.Fatal(err)
	}
	_ = m.Close()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	select {
	case <-s.Done():
	case <-ctx.Done():
		t.Fatal("PacketIO close did not stop stack")
	}
	_ = s.Close()
	if _, err = s.ListenUDP(netip.AddrPort{}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("listen after close: %v", err)
	}
}
