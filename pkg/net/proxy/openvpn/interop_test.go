//go:build openvpn_interop

package openvpn

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/openvpn/native"
)

func interopConfig(t testing.TB) Config {
	t.Helper()
	dir := os.Getenv("OPENVPN_TEST_STATE")
	if dir == "" {
		t.Skip("set OPENVPN_TEST_STATE and OPENVPN_TEST_GATEWAY")
	}
	read := func(name string) string {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	cfg := Config{Config: native.Config{
		Gateway: os.Getenv("OPENVPN_TEST_GATEWAY"), Network: os.Getenv("OPENVPN_TEST_NETWORK"),
		CACertPEM: read("ca.crt"), ClientCertPEM: read("client.crt"), ClientKeyPEM: read("client.key"),
		Username: "alice", Password: "test-password", KeyDirection: 1, MTU: 1400,
	}}
	if os.Getenv("OPENVPN_TEST_NO_CERT") == "1" {
		cfg.ClientCertPEM, cfg.ClientKeyPEM = "", ""
	}
	switch os.Getenv("OPENVPN_TEST_PROTECTION") {
	case "tls-auth":
		cfg.TLSAuthKey = read("ta.key")
		cfg.Auth = "SHA256"
	case "none":
	default:
		cfg.TLSCryptKey = read("ta.key")
	}
	if cipher := os.Getenv("OPENVPN_TEST_CIPHER"); cipher != "" {
		cfg.DataCiphers = []string{cipher}
	}
	return cfg
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
	payload := bytes.Repeat([]byte("openvpn-real-tcp"), 8192)
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
func TestOfficialOpenVPN(t *testing.T) {
	cfg := interopConfig(t)
	client, err := NewClient(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	for _, target := range []string{"10.88.0.1", "fd88::1"} {
		t.Run(target, func(t *testing.T) { echoTCP(t, client, target); echoUDP(t, client, target) })
	}
	info := client.NodeExtraInfo().OpenVPN
	if info == nil || len(info.TunnelPrefixes) != 2 || len(info.DNS) != 1 || len(info.Routes) != 1 {
		t.Fatalf("missing pushed config: %+v", info)
	}
	t.Logf("negotiated: %+v", info)
	// Check active keepalive beyond the server's five-second ping-restart.
	timer := time.NewTimer(6 * time.Second)
	defer timer.Stop()
	select {
	case <-client.ctx.Done():
		t.Fatalf("tunnel ended: %v", client.session.Err())
	case <-timer.C:
	}
	echoTCP(t, client, "10.88.0.1")
}
func TestOfficialOpenVPNBadCredentials(t *testing.T) {
	cfg := interopConfig(t)
	cfg.Password = "wrong"
	client, err := NewClient(cfg, nil)
	if client != nil {
		_ = client.Close()
	}
	if err == nil {
		t.Fatal("server accepted incorrect password")
	}
	t.Logf("rejected: %v", err)
}
func TestOfficialOpenVPNUntrustedCA(t *testing.T) {
	cfg := interopConfig(t)
	cfg.CACertPEM = ""
	client, err := NewClient(cfg, nil)
	if client != nil {
		_ = client.Close()
	}
	if err == nil {
		t.Fatal("untrusted server accepted")
	}
}
func TestOfficialOpenVPNReconnect(t *testing.T) {
	cfg := interopConfig(t)
	cfg.AutoReconnect = true
	cfg.RenegotiateAfter = time.Hour
	proxy, err := NewOutbound(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proxy.Close() })
	echoTCP(t, proxy, "10.88.0.1")
	r := proxy.(*reconnectingClient)
	r.mu.RLock()
	first := r.current
	r.mu.RUnlock()
	_ = first.session.Close()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	case <-timer.C:
	}
	echoTCP(t, proxy, "10.88.0.1")
	echoUDP(t, proxy, "10.88.0.1")
}
func BenchmarkOfficialOpenVPNTCP(b *testing.B) {
	cfg := interopConfig(b)
	client, err := NewClient(cfg, nil)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = client.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	addr, err := netapi.ParseAddress("tcp", "10.88.0.1:19991")
	if err != nil {
		b.Fatal(err)
	}
	conn, err := client.Conn(ctx, addr)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(3 * time.Minute)); err != nil {
		b.Fatal(err)
	}
	const size = 16 << 20
	payload := bytes.Repeat([]byte("benchmark"), 8192)
	b.SetBytes(size)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		done := make(chan error, 1)
		go func() { _, err := io.CopyN(io.Discard, conn, size); done <- err }()
		for sent := 0; sent < size; {
			n, err := conn.Write(payload[:min(len(payload), size-sent)])
			if err != nil {
				b.Fatal(err)
			}
			sent += n
		}
		if err := <-done; err != nil {
			b.Fatal(err)
		}
	}
}
func BenchmarkOfficialOpenVPNUDPRoundTrip(b *testing.B) {
	cfg := interopConfig(b)
	client, err := NewClient(cfg, nil)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = client.Close() })
	addr, err := netapi.ParseAddress("udp", "10.88.0.1:19992")
	if err != nil {
		b.Fatal(err)
	}
	conn, err := client.PacketConn(context.Background(), addr)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(time.Minute)); err != nil {
		b.Fatal(err)
	}
	payload, got := bytes.Repeat([]byte("a"), 1200), make([]byte, 1500)
	b.SetBytes(1200)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := conn.WriteTo(payload, addr); err != nil {
			b.Fatal(err)
		}
		n, _, err := conn.ReadFrom(got)
		if err != nil {
			b.Fatal(err)
		}
		if !bytes.Equal(got[:n], payload) {
			b.Fatal("UDP echo corrupt")
		}
	}
}

func TestOfficialOpenVPNRekey(t *testing.T) {
	cfg := interopConfig(t)
	c, err := NewClient(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	addr, err := netapi.ParseAddress("tcp", "10.88.0.1:19991")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := c.Conn(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	for range 9 {
		if err := c.session.Rekey(ctx); err != nil {
			t.Fatal(err)
		}
		payload := []byte("persistent TCP after rekey")
		if _, err := conn.Write(payload); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatal("corrupt rekey TCP echo")
		}
		echoUDP(t, c, "fd88::1")
	}
}

func TestOfficialOpenVPNServerDrivenRekey(t *testing.T) {
	if os.Getenv("OPENVPN_TEST_SERVER_REKEY") != "1" {
		t.Skip("needs a two-second server renegotiation interval")
	}
	cfg := interopConfig(t)
	c, err := NewClient(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	addr, err := netapi.ParseAddress("tcp", "10.88.0.1:19991")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := c.Conn(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload := []byte("TCP across server key ID wrap")
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for range 24 {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-tick.C:
		}
		if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write(payload); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatal("corrupt echo")
		}
	}
	if c.session.RekeyCount() < 8 {
		t.Fatalf("server rekey did not wrap key IDs: %d", c.session.RekeyCount())
	}
	t.Logf("successful server rekeys: %d", c.session.RekeyCount())
}
