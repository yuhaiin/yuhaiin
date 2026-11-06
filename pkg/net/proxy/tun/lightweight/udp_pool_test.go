package lightweight

import (
	"bytes"
	"errors"
	"net/netip"
	"os"
	"testing"
	"time"
)

// Queued datagrams live in pooled stack buffers. Reading them out in bursts
// must preserve order, payloads and sources across queue reuse, and closing
// the stacks must return every buffer and queue charge.
func TestUDPPooledQueueReuse(t *testing.T) {
	a, b := stackPair(t)
	dst := netip.MustParseAddrPort("192.0.2.2:9100")
	server, err := b.ListenUDP(dst)
	if err != nil {
		t.Fatal(err)
	}
	client, err := a.DialUDP(netip.AddrPort{}, dst)
	if err != nil {
		t.Fatal(err)
	}
	clientAddr := netip.MustParseAddrPort(client.LocalAddr().String())
	_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2048)
	for round := range 5 {
		const burst = 16
		for i := range burst {
			payload := bytes.Repeat([]byte{byte(round*burst + i)}, 1+i*97)
			if _, err := client.Write(payload); err != nil {
				t.Fatal(err)
			}
		}
		for i := range burst {
			n, from, err := server.ReadFromUDPAddrPort(buf)
			if err != nil {
				t.Fatal(err)
			}
			want := bytes.Repeat([]byte{byte(round*burst + i)}, 1+i*97)
			if !bytes.Equal(buf[:n], want) || from != clientAddr {
				t.Fatalf("round %d datagram %d: %d bytes from %s", round, i, n, from)
			}
		}
	}
	// Leave datagrams queued so Close must release them.
	for range 4 {
		if _, err := client.Write([]byte("pending")); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(50 * time.Millisecond)
	_ = client.Close()
	_ = server.Close()
	_ = a.Close()
	_ = b.Close()
	if a.Stats().MemoryBytes != 0 || b.Stats().MemoryBytes != 0 {
		t.Fatalf("memory retained after close: %d %d", a.Stats().MemoryBytes, b.Stats().MemoryBytes)
	}
}

// A blocked read reuses one deadline timer. Reuse must neither fire a stale
// expiry early nor miss a later deadline.
func TestUDPReadDeadlineTimerReuse(t *testing.T) {
	a, b := stackPair(t)
	defer a.Close()
	defer b.Close()
	dst := netip.MustParseAddrPort("192.0.2.2:9101")
	server, err := b.ListenUDP(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := a.DialUDP(netip.AddrPort{}, dst)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	buf := make([]byte, 64)
	for range 3 {
		_ = server.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
		if _, _, err := server.ReadFrom(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("expected deadline, got %v", err)
		}
	}
	if server.readTimer == nil {
		t.Fatal("deadline timer was not kept for reuse")
	}
	_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
	go func() {
		time.Sleep(100 * time.Millisecond)
		_, _ = client.Write([]byte("late"))
	}()
	start := time.Now()
	n, _, err := server.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "late" {
		t.Fatalf("read after timer reuse: %q %v", buf[:n], err)
	}
	if time.Since(start) < 50*time.Millisecond {
		t.Fatal("read returned before the datagram arrived")
	}
}
