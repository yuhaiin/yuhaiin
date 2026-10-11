//go:build amneziawg_interop

package amneziawg

import (
	"context"
	"io"
	"os"
	"testing"
	"time"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer/interfaces"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

func TestOfficialAmneziaWGServerTCPAndUDP(t *testing.T) {
	if !amneziaWGInteropConfigured() {
		t.Skip("set AMNEZIAWG_TEST_* variables to run the official AmneziaWG server test")
	}
	c := newAmneziaWGInteropClient(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	tcpAddress, err := netapi.ParseAddress("tcp", "10.8.0.1:4243")
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := c.Conn(ctx, tcpAddress)
	if err != nil {
		t.Fatalf("TCP dial through tunnel: %v", err)
	}
	defer tcp.Close()
	if err := tcp.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := tcp.Write([]byte("amneziawg TCP")); err != nil {
		t.Fatal(err)
	}
	tcpReply := make([]byte, len("amneziawg TCP"))
	if _, err := io.ReadFull(tcp, tcpReply); err != nil {
		t.Fatal(err)
	}
	if string(tcpReply) != "amneziawg TCP" {
		t.Fatalf("TCP echo = %q", tcpReply)
	}

	udpAddress, err := netapi.ParseAddress("udp", "10.8.0.1:4242")
	if err != nil {
		t.Fatal(err)
	}
	udp, err := c.PacketConn(ctx, udpAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	if err := udp.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := udp.WriteTo([]byte("amneziawg UDP"), udpAddress); err != nil {
		t.Fatal(err)
	}
	udpReply := make([]byte, 64)
	n, _, err := udp.ReadFrom(udpReply)
	if err != nil {
		t.Fatal(err)
	}
	if string(udpReply[:n]) != "amneziawg UDP" {
		t.Fatalf("UDP echo = %q", udpReply[:n])
	}
}

func BenchmarkOfficialAmneziaWGTCPConnect(b *testing.B) {
	if !amneziaWGInteropConfigured() {
		b.Skip("set AMNEZIAWG_TEST_* variables to run the official AmneziaWG benchmark")
	}
	c := newAmneziaWGInteropClient(b)
	address, err := netapi.ParseAddress("tcp", "10.8.0.1:4243")
	if err != nil {
		b.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(b.Context(), 10*time.Second)
	conn, err := c.Conn(ctx, address)
	cancel()
	if err != nil {
		b.Fatal(err)
	}
	_ = conn.Close() // establish the WireGuard session before timing TCP dials

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		ctx, cancel := context.WithTimeout(b.Context(), 10*time.Second)
		conn, err := c.Conn(ctx, address)
		cancel()
		if err != nil {
			b.Fatal(err)
		}
		_ = conn.Close()
	}
}

func BenchmarkOfficialAmneziaWGUDPEcho(b *testing.B) {
	if !amneziaWGInteropConfigured() {
		b.Skip("set AMNEZIAWG_TEST_* variables to run the official AmneziaWG benchmark")
	}
	c := newAmneziaWGInteropClient(b)
	address, err := netapi.ParseAddress("udp", "10.8.0.1:4242")
	if err != nil {
		b.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(b.Context(), 10*time.Second)
	conn, err := c.PacketConn(ctx, address)
	cancel()
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()
	payload := []byte("amneziawg benchmark packet")
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		b.Fatal(err)
	}
	if _, err := conn.WriteTo(payload, address); err != nil {
		b.Fatal(err)
	}
	warmup := make([]byte, len(payload))
	n, _, err := conn.ReadFrom(warmup)
	if err != nil {
		b.Fatal(err)
	}
	if string(warmup[:n]) != string(payload) {
		b.Fatalf("UDP warmup echo = %q", warmup[:n])
	}
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	buf := make([]byte, len(payload))
	for b.Loop() {
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			b.Fatal(err)
		}
		if _, err := conn.WriteTo(payload, address); err != nil {
			b.Fatal(err)
		}
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			b.Fatal(err)
		}
		if string(buf[:n]) != string(payload) {
			b.Fatalf("UDP echo = %q", buf[:n])
		}
	}
}

func amneziaWGInteropConfigured() bool {
	return os.Getenv("AMNEZIAWG_TEST_CLIENT_PRIVATE_KEY") != "" &&
		os.Getenv("AMNEZIAWG_TEST_SERVER_PUBLIC_KEY") != "" &&
		os.Getenv("AMNEZIAWG_TEST_ENDPOINT") != ""
}

func newAmneziaWGInteropClient(tb testing.TB) *Client {
	tb.Helper()
	// The test endpoint is Podman's loopback-published UDP port. Keep the
	// test socket unbound so the host's physical default interface cannot
	// reject loopback traffic.
	interfaces.SetDefaultInterfaceName("")
	client := contractnode.AmneziaWG{
		SecretKey: os.Getenv("AMNEZIAWG_TEST_CLIENT_PRIVATE_KEY"),
		Endpoint:  []string{"10.8.0.2/24"},
		JC:        4,
		JMin:      40,
		JMax:      70,
		Peers: []contractnode.WireguardPeer{{
			PublicKey:  os.Getenv("AMNEZIAWG_TEST_SERVER_PUBLIC_KEY"),
			Endpoint:   os.Getenv("AMNEZIAWG_TEST_ENDPOINT"),
			AllowedIPs: []string{"10.8.0.1/32"},
			KeepAlive:  1,
		}},
	}
	c, err := NewClient(client, nil)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = c.Close() })
	return c
}
