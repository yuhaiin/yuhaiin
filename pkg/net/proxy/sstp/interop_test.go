//go:build sstp_interop

package sstp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/internal/testutil"
	client "github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit/session"
)

func TestSoftEtherSSTPConnect(t *testing.T) {
	if os.Getenv("SSTP_TEST_GATEWAY") == "" {
		t.Skip("set SSTP_TEST_GATEWAY to run the SoftEther integration test")
	}
	_, sess, result := dialSoftEther(t, "test-password")
	if result.AssignedIP.To4() == nil {
		t.Fatalf("assigned IP = %v, want IPv4", result.AssignedIP)
	}
	if err := sess.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSoftEtherSSTPRejectsBadPassword(t *testing.T) {
	if os.Getenv("SSTP_TEST_GATEWAY") == "" {
		t.Skip("set SSTP_TEST_GATEWAY to run the SoftEther integration test")
	}
	dev, unregister := newSSTPTestTUN(t)
	defer unregister()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	_, _, err := Dial(ctx, softEtherConfig("wrong-password", dev.Name()))
	if !errors.Is(err, client.ErrAuth) {
		t.Fatalf("Dial() error = %v, want client.ErrAuth", err)
	}
}

func TestSoftEtherSSTPReconnectAfterClose(t *testing.T) {
	if os.Getenv("SSTP_TEST_GATEWAY") == "" {
		t.Skip("set SSTP_TEST_GATEWAY to run the SoftEther integration test")
	}
	for range 2 {
		_, sess, result := dialSoftEther(t, "test-password")
		if result.AssignedIP.To4() == nil {
			t.Fatalf("assigned IP = %v, want IPv4", result.AssignedIP)
		}
		if err := sess.Close(); err != nil {
			t.Fatalf("close SSTP session: %v", err)
		}
		waitCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		_ = sess.Wait(waitCtx)
		if err := waitCtx.Err(); err != nil {
			cancel()
			t.Fatalf("SSTP session did not stop after close: %v", err)
		}
		cancel()
	}
}

func BenchmarkSoftEtherSSTPConnect(b *testing.B) {
	if os.Getenv("SSTP_TEST_GATEWAY") == "" {
		b.Skip("set SSTP_TEST_GATEWAY to run the SoftEther benchmark")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		dev, unregister := newSSTPTestTUN(b)
		sess, _, err := Dial(b.Context(), softEtherConfig("test-password", dev.Name()))
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

func newSSTPTestTUN(tb testing.TB) (*testutil.VirtualTUN, func()) {
	tb.Helper()
	dev, unregister, err := testutil.NewVirtualTUN(fmt.Sprintf("sstp-%d", time.Now().UnixNano()))
	if err != nil {
		tb.Fatal(err)
	}
	return dev, unregister
}

func dialSoftEther(tb testing.TB, password string) (*testutil.VirtualTUN, client.Session, client.Result) {
	tb.Helper()
	dev, unregister := newSSTPTestTUN(tb)
	ctx, cancel := context.WithTimeout(tb.Context(), 30*time.Second)
	defer cancel()
	sess, result, err := Dial(ctx, softEtherConfig(password, dev.Name()))
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

func softEtherConfig(password, tunName string) Config {
	port := 443
	if value := os.Getenv("SSTP_TEST_PORT"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 65535 {
			panic("invalid SSTP_TEST_PORT " + value)
		}
		port = parsed
	}
	return Config{
		Server:     os.Getenv("SSTP_TEST_GATEWAY"),
		Port:       port,
		Username:   "alice",
		Password:   password,
		TUNName:    tunName,
		SkipVerify: true,
	}
}
