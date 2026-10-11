//go:build ikev2_interop

package ike

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/internal/testutil"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit/dataplane"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit/vlog"
)

func TestStrongSwanIKEv2UDP(t *testing.T) {
	if os.Getenv("IKEV2_TEST_GATEWAY") == "" {
		t.Skip("set IKEV2_TEST_GATEWAY to run the strongSwan integration test")
	}
	client, result := connectStrongSwan(t, "test-password")
	tunnel, err := result.BuildTunnel()
	if err != nil {
		t.Fatal(err)
	}

	want := []byte("strongSwan ESP UDP echo")
	got := strongSwanUDPEcho(t, client, tunnel, result.AssignedIP, want)
	if !bytes.Equal(got, want) {
		t.Fatalf("UDP echo = %q, want %q", got, want)
	}
}

func TestStrongSwanIKEv2RejectsBadPassword(t *testing.T) {
	if os.Getenv("IKEV2_TEST_GATEWAY") == "" {
		t.Skip("set IKEV2_TEST_GATEWAY to run the strongSwan integration test")
	}
	cfg := strongSwanConfig("wrong-password")
	client := NewClient(cfg)
	defer client.Close()
	if _, err := client.Connect(); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("Connect() error = %v, want ErrAuthFailed", err)
	}
}

func BenchmarkStrongSwanIKEv2Connect(b *testing.B) {
	if os.Getenv("IKEV2_TEST_GATEWAY") == "" {
		b.Skip("set IKEV2_TEST_GATEWAY to run the strongSwan benchmark")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		client := NewClient(strongSwanConfig("test-password"))
		if _, err := client.Connect(); err != nil {
			b.Fatal(err)
		}
		if err := client.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStrongSwanIKEv2UDPEcho(b *testing.B) {
	if os.Getenv("IKEV2_TEST_GATEWAY") == "" {
		b.Skip("set IKEV2_TEST_GATEWAY to run the strongSwan benchmark")
	}
	client, result := connectStrongSwanBenchmark(b)
	tunnel, err := result.BuildTunnel()
	if err != nil {
		b.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x5a}, 1024)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if got := strongSwanUDPEchoBenchmark(b, client, tunnel, result.AssignedIP, payload); !bytes.Equal(got, payload) {
			b.Fatal("UDP echo payload mismatch")
		}
	}
}

func connectStrongSwan(t *testing.T, password string) (*Client, *ClientResult) {
	t.Helper()
	client := NewClient(strongSwanConfig(password))
	t.Cleanup(func() { _ = client.Close() })
	result, err := client.Connect()
	if err != nil {
		t.Fatal(err)
	}
	return client, result
}

func connectStrongSwanBenchmark(b *testing.B) (*Client, *ClientResult) {
	b.Helper()
	client := NewClient(strongSwanConfig("test-password"))
	b.Cleanup(func() { _ = client.Close() })
	result, err := client.Connect()
	if err != nil {
		b.Fatal(err)
	}
	return client, result
}

func strongSwanConfig(password string) ClientConfig {
	port := envPort("IKEV2_TEST_PORT", 500)
	nattPort := envPort("IKEV2_TEST_NATT_PORT", 4500)
	return ClientConfig{
		ServerHost:  envString("IKEV2_TEST_GATEWAY", "127.0.0.1"),
		ServerPort:  port,
		NATTPort:    nattPort,
		PSK:         []byte("test-ike-psk"),
		LocalID:     FQDNIdentity("alice"),
		RemoteID:    identityPointer(FQDNIdentity("vpn.test")),
		EAPUsername: "alice",
		EAPPassword: password,
		Logger:      vlog.Text(io.Discard),
	}
}

func strongSwanUDPEcho(t *testing.T, client *Client, tunnel dataplane.Tunnel, src net.IP, data []byte) []byte {
	t.Helper()
	got, err := strongSwanUDPEchoPacket(client, tunnel, src, data)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func strongSwanUDPEchoBenchmark(b *testing.B, client *Client, tunnel dataplane.Tunnel, src net.IP, data []byte) []byte {
	b.Helper()
	got, err := strongSwanUDPEchoPacket(client, tunnel, src, data)
	if err != nil {
		b.Fatal(err)
	}
	return got
}

func strongSwanUDPEchoPacket(client *Client, tunnel dataplane.Tunnel, src net.IP, data []byte) ([]byte, error) {
	inner := testutil.IPv4UDP(src, net.IPv4(127, 0, 0, 1), 40123, 4242, data)
	packet, err := tunnel.Encapsulate(inner)
	if err != nil {
		return nil, err
	}
	conn := client.DataConn()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return nil, err
	}
	if _, err := conn.Write(packet); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	response, err := tunnel.Decapsulate(buf[:n])
	if err != nil {
		return nil, err
	}
	return testutil.IPv4UDPData(response)
}

func envString(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func envPort(name string, fallback int) int {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		panic("invalid " + name + " value " + value)
	}
	return port
}

func identityPointer(id Identity) *Identity { return &id }
