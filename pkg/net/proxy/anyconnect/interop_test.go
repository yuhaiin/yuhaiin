//go:build anyconnect_interop

package anyconnect

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/internal/testutil"
	client "github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit/session"
)

func TestOcservAnyConnectUDP(t *testing.T) {
	if os.Getenv("ANYCONNECT_TEST_GATEWAY") == "" {
		t.Skip("set ANYCONNECT_TEST_GATEWAY to run the ocserv integration test")
	}
	dev, sess, result := dialOcserv(t, "test-password")
	if result.AssignedIP.To4() == nil {
		t.Fatalf("assigned IP = %v, want IPv4", result.AssignedIP)
	}

	want := []byte("ocserv CSTP UDP echo")
	if got := ocservUDPEcho(t, dev, result.AssignedIP, want); !bytes.Equal(got, want) {
		t.Fatalf("UDP echo = %q, want %q", got, want)
	}
	if err := sess.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOcservAnyConnectRejectsBadPassword(t *testing.T) {
	if os.Getenv("ANYCONNECT_TEST_GATEWAY") == "" {
		t.Skip("set ANYCONNECT_TEST_GATEWAY to run the ocserv integration test")
	}
	dev, unregister := registerAnyConnectTestTUN(t)
	defer unregister()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	_, _, err := Dial(ctx, ocservConfig("wrong-password", dev.Name()))
	if !errors.Is(err, client.ErrAuth) {
		t.Fatalf("Dial() error = %v, want client.ErrAuth", err)
	}
}

func TestOcservAnyConnectReconnectAfterClose(t *testing.T) {
	if os.Getenv("ANYCONNECT_TEST_GATEWAY") == "" {
		t.Skip("set ANYCONNECT_TEST_GATEWAY to run the ocserv integration test")
	}
	for range 2 {
		dev, sess, result := dialOcserv(t, "test-password")
		want := []byte("ocserv reconnect UDP echo")
		if got := ocservUDPEcho(t, dev, result.AssignedIP, want); !bytes.Equal(got, want) {
			t.Fatalf("UDP echo = %q, want %q", got, want)
		}
		if err := sess.Close(); err != nil {
			t.Fatalf("close AnyConnect session: %v", err)
		}
		waitCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		_ = sess.Wait(waitCtx)
		if err := waitCtx.Err(); err != nil {
			cancel()
			t.Fatalf("AnyConnect session did not stop after close: %v", err)
		}
		cancel()
	}
}

func BenchmarkOcservAnyConnectConnect(b *testing.B) {
	if os.Getenv("ANYCONNECT_TEST_GATEWAY") == "" {
		b.Skip("set ANYCONNECT_TEST_GATEWAY to run the ocserv benchmark")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		dev, unregister := registerAnyConnectTestTUN(b)
		sess, _, err := Dial(b.Context(), ocservConfig("test-password", dev.Name()))
		if err != nil {
			unregister()
			b.Fatal(err)
		}
		if err := sess.Close(); err != nil {
			unregister()
			b.Fatal(err)
		}
		unregister()
	}
}

func BenchmarkOcservAnyConnectUDPEcho(b *testing.B) {
	if os.Getenv("ANYCONNECT_TEST_GATEWAY") == "" {
		b.Skip("set ANYCONNECT_TEST_GATEWAY to run the ocserv benchmark")
	}
	dev, sess, result := dialOcserv(b, "test-password")
	b.Cleanup(func() { _ = sess.Close() })
	payload := bytes.Repeat([]byte{0x5a}, 1024)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if got := ocservUDPEchoBenchmark(b, dev, result.AssignedIP, payload); !bytes.Equal(got, payload) {
			b.Fatal("UDP echo payload mismatch")
		}
	}
}

func registerAnyConnectTestTUN(tb testing.TB) (*testutil.VirtualTUN, func()) {
	tb.Helper()
	dev, unregister, err := testutil.NewVirtualTUN(fmt.Sprintf("ac-%d", time.Now().UnixNano()))
	if err != nil {
		tb.Fatal(err)
	}
	return dev, unregister
}

func dialOcserv(tb testing.TB, password string) (*testutil.VirtualTUN, client.Session, client.Result) {
	tb.Helper()
	dev, unregister := registerAnyConnectTestTUN(tb)
	ctx, cancel := context.WithTimeout(tb.Context(), 30*time.Second)
	defer cancel()
	sess, result, err := Dial(ctx, ocservConfig(password, dev.Name()))
	if err != nil {
		unregister()
		tb.Fatal(err)
	}
	tb.Cleanup(func() {
		_ = sess.Close()
		unregister()
	})
	return dev, sess, result
}

func ocservConfig(password, tunName string) Config {
	port := 8443
	if value := os.Getenv("ANYCONNECT_TEST_PORT"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 65535 {
			panic("invalid ANYCONNECT_TEST_PORT " + value)
		}
		port = parsed
	}
	return Config{
		Server:   os.Getenv("ANYCONNECT_TEST_GATEWAY"),
		Port:     port,
		Username: "alice",
		Password: password,
		Insecure: true,
		NoDTLS:   true,
		TUNName:  tunName,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func ocservUDPEcho(tb testing.TB, dev *testutil.VirtualTUN, src net.IP, data []byte) []byte {
	tb.Helper()
	got, err := ocservUDPEchoPacket(tb.Context(), dev, src, data)
	if err != nil {
		tb.Fatal(err)
	}
	return got
}

func ocservUDPEchoBenchmark(b *testing.B, dev *testutil.VirtualTUN, src net.IP, data []byte) []byte {
	b.Helper()
	got, err := ocservUDPEchoPacket(b.Context(), dev, src, data)
	if err != nil {
		b.Fatal(err)
	}
	return got
}

func ocservUDPEchoPacket(ctx context.Context, dev *testutil.VirtualTUN, src net.IP, data []byte) ([]byte, error) {
	packet := testutil.IPv4UDP(src, net.IPv4(192, 168, 222, 1), 40123, 4242, data)
	if err := dev.Send(packet); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	for {
		reply, err := dev.Receive(ctx)
		if err != nil {
			return nil, fmt.Errorf("ocserv UDP echo: %w", err)
		}
		// ocserv may send IPv6 neighbor discovery after connecting even when
		// this fixture only tests the IPv4 data path.
		data, err := testutil.IPv4UDPData(reply)
		if err == nil {
			return data, nil
		}
	}
}
