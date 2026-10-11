//go:build l2tp_interop

package l2tp

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/l2tp/native"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

func TestLinuxL2TPv3(t *testing.T) {
	gateway := os.Getenv("L2TPV3_TEST_GATEWAY")
	if gateway == "" {
		t.Skip("set L2TPV3_TEST_GATEWAY")
	}
	cfg := v3InteropConfig(t)
	c, err := NewClient(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, target := range []string{"10.89.0.1", "fd89::1"} {
		t.Run(target, func(t *testing.T) { echoTCP(t, c, target); echoUDP(t, c, target) })
	}
}

func TestOfficialL2TPConnect(t *testing.T) {
	gateway := os.Getenv("L2TP_TEST_GATEWAY")
	if gateway == "" {
		t.Skip("set L2TP_TEST_GATEWAY")
	}
	c, err := NewClient(v2InteropConfig(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	t.Logf("negotiated %+v", c.NodeExtraInfo().L2TP)
	if target := os.Getenv("L2TP_TEST_TARGET"); target != "" {
		echoTCP(t, c, target)
		echoUDP(t, c, target)
	}
	if os.Getenv("L2TP_TEST_IPV6") == "1" {
		echoTCP(t, c, "fd88::1")
		echoUDP(t, c, "fd88::1")
	}
	if info := c.NodeExtraInfo().L2TP; info == nil || len(info.TunnelPrefixes) == 0 {
		t.Fatal("missing IPCP lease")
	}
}

func echoTCP(t testing.TB, proxy netapi.Proxy, target string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	addr, err := netapi.ParseAddress("tcp", net.JoinHostPort(target, "19991"))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := proxy.Conn(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("l2tp-real-tcp"), 8192)
	completed := make(chan error, 1)
	go func() { _, err := io.Copy(conn, bytes.NewReader(payload)); completed <- err }()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if err := <-completed; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("TCP payload mismatch")
	}
}
func echoUDP(t testing.TB, proxy netapi.Proxy, target string) {
	t.Helper()
	addr, err := netapi.ParseAddress("udp", net.JoinHostPort(target, "19992"))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := proxy.PacketConn(context.Background(), addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	for size := range []int{1, 128, 1200} {
		payload := bytes.Repeat([]byte{byte(size + 1)}, []int{1, 128, 1200}[size])
		if _, err := conn.WriteTo(payload, addr); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, 1500)
		n, _, err := conn.ReadFrom(got)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got[:n], payload) {
			t.Fatal("UDP payload mismatch")
		}
	}
}

func v2InteropConfig(t testing.TB) Config {
	t.Helper()
	gateway := os.Getenv("L2TP_TEST_GATEWAY")
	if gateway == "" {
		t.Skip("set L2TP_TEST_GATEWAY")
	}
	cfg := Config{Version: 2, Gateway: gateway, Username: "alice", Password: "test-password", AuthType: os.Getenv("L2TP_TEST_AUTH"), SharedSecret: os.Getenv("L2TP_TEST_SECRET")}
	if os.Getenv("L2TP_TEST_IPV6") == "1" {
		cfg.IPv6 = true
		cfg.IPv6Address = "fd88::2/64"
	}
	return cfg
}
func v3InteropConfig(t testing.TB) Config {
	t.Helper()
	gateway := os.Getenv("L2TPV3_TEST_GATEWAY")
	if gateway == "" {
		t.Skip("set L2TPV3_TEST_GATEWAY")
	}
	cookie := func(key string) []byte {
		b, err := hex.DecodeString(os.Getenv(key))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	return Config{Version: 3, Gateway: gateway, Static: os.Getenv("L2TPV3_TEST_DYNAMIC") != "1", SharedSecret: os.Getenv("L2TPV3_TEST_SECRET"), LocalSessionID: 100, PeerSessionID: 200, LocalCookie: cookie("L2TPV3_TEST_LOCAL_COOKIE"), PeerCookie: cookie("L2TPV3_TEST_PEER_COOKIE"), Sublayer: os.Getenv("L2TPV3_TEST_SUBLAYER") == "default", Address: "10.89.0.2/24", Router: "10.89.0.1", IPv6Address: "fd89::2/64", IPv6Router: "fd89::1"}
}
func TestOfficialL2TPBadCredentials(t *testing.T) {
	cfg := v2InteropConfig(t)
	cfg.Password = "wrong"
	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Second)
	defer cancel()
	c, err := connectClient(ctx, cfg, nil)
	if c != nil {
		_ = c.Close()
	}
	if err == nil {
		t.Fatal("accepted incorrect PPP password")
	}
	if !errors.Is(err, native.ErrAuth) {
		t.Fatalf("wrong authentication error: %v", err)
	}
}
func TestOfficialL2TPReconnect(t *testing.T) {
	cfg := v2InteropConfig(t)
	cfg.AutoReconnect = true
	r, err := newReconnectingClient(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	first := r.current
	old := first.session.Info().LocalSessionID
	_ = first.session.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	next, err := r.available(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if next == first || next.session.Info().LocalSessionID == old {
		t.Fatal("reconnect reused terminated session")
	}
	if target := os.Getenv("L2TP_TEST_TARGET"); target != "" {
		echoTCP(t, r, target)
		echoUDP(t, r, target)
	}
}
func TestLinuxL2TPv3RejectsWrongCookie(t *testing.T) {
	cfg := v3InteropConfig(t)
	if !cfg.Static || len(cfg.LocalCookie) == 0 {
		t.Skip("needs a static cookie session")
	}
	cfg.LocalCookie = bytes.Clone(cfg.LocalCookie)
	cfg.LocalCookie[0] ^= 1
	c, err := NewClient(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	addr := netapi.ParseIPAddr("udp", net.ParseIP("10.89.0.1"), 19992)
	conn, err := c.PacketConn(t.Context(), addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(700 * time.Millisecond))
	if _, err = conn.WriteTo([]byte("cookie-rejection"), addr); err != nil {
		t.Fatal(err)
	}
	_, _, err = conn.ReadFrom(make([]byte, 1500))
	timeout, ok := errors.AsType[net.Error](err)
	if !ok || !timeout.Timeout() {
		t.Fatalf("expected cookie rejection timeout, got %v", err)
	}
}
func BenchmarkRealL2TP(b *testing.B) {
	benchmarkTunnel(b, v2InteropConfig(b), os.Getenv("L2TP_TEST_TARGET"))
}
func BenchmarkRealL2TPv3(b *testing.B) { benchmarkTunnel(b, v3InteropConfig(b), "10.89.0.1") }
func benchmarkTunnel(b *testing.B, cfg Config, target string) {
	if target == "" {
		b.Skip("set echo target")
	}
	c, err := NewClient(cfg, nil)
	if err != nil {
		b.Fatal(err)
	}
	defer c.Close()
	b.Run("TCP", func(b *testing.B) {
		addr, err := netapi.ParseAddress("tcp", net.JoinHostPort(target, "19991"))
		if err != nil {
			b.Fatal(err)
		}
		conn, err := c.Conn(b.Context(), addr)
		if err != nil {
			b.Fatal(err)
		}
		defer conn.Close()
		payload := bytes.Repeat([]byte{0xa5}, 256*1024)
		received := make([]byte, len(payload))
		b.SetBytes(int64(len(payload)))
		for b.Loop() {
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			done := make(chan error, 1)
			go func() { _, err := conn.Write(payload); done <- err }()
			if _, err := io.ReadFull(conn, received); err != nil {
				b.Fatal(err)
			}
			if err := <-done; err != nil {
				b.Fatal(err)
			}
			if !bytes.Equal(received, payload) {
				b.Fatal("TCP benchmark payload mismatch")
			}
		}
	})
	b.Run("UDP", func(b *testing.B) {
		addr, err := netapi.ParseAddress("udp", net.JoinHostPort(target, "19992"))
		if err != nil {
			b.Fatal(err)
		}
		conn, err := c.PacketConn(b.Context(), addr)
		if err != nil {
			b.Fatal(err)
		}
		defer conn.Close()
		payload := bytes.Repeat([]byte{0x5a}, 1200)
		received := make([]byte, 1500)
		b.SetBytes(int64(len(payload)))
		for b.Loop() {
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := conn.WriteTo(payload, addr); err != nil {
				b.Fatal(err)
			}
			n, _, err := conn.ReadFrom(received)
			if err != nil {
				b.Fatal(err)
			}
			if !bytes.Equal(received[:n], payload) {
				b.Fatal("UDP benchmark payload mismatch")
			}
		}
	})
}

func TestLinuxL2TPv3RejectsWrongSecret(t *testing.T) {
	cfg := v3InteropConfig(t)
	if cfg.Static || cfg.SharedSecret == "" {
		t.Skip("needs authenticated dynamic signalling")
	}
	cfg.SharedSecret = "incorrect-test-secret"
	ctx, cancel := context.WithTimeout(t.Context(), 700*time.Millisecond)
	defer cancel()
	c, err := connectClient(ctx, cfg, nil)
	if c != nil {
		_ = c.Close()
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected unauthenticated control messages to be discarded: %v", err)
	}
}
