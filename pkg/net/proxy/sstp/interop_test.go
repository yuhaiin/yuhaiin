//go:build sstp_interop

package sstp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
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

func TestSoftEtherSSTPProxyEcho(t *testing.T) {
	proxy, target := dialSoftEtherProxy(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	tcpAddr, err := netapi.ParseAddress("tcp", net.JoinHostPort(target, "19991"))
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := proxy.Conn(ctx, tcpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	if err := tcp.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("sstp-real-tcp"), 4096)
	if err := sstpTCPEcho(tcp, payload, make([]byte, len(payload))); err != nil {
		t.Fatalf("TCP echo through SSTP: %v", err)
	}

	udpAddr, err := netapi.ParseAddress("udp", net.JoinHostPort(target, "19992"))
	if err != nil {
		t.Fatal(err)
	}
	udp, err := proxy.PacketConn(ctx, udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	if err := udp.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	udpPayload := []byte("sstp-real-udp")
	if err := sstpUDPEcho(udp, udpAddr, udpPayload, make([]byte, 1500)); err != nil {
		t.Fatalf("UDP echo through SSTP: %v", err)
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

func BenchmarkSoftEtherSSTPTCPEcho(b *testing.B) {
	proxy, target := dialSoftEtherProxy(b)
	ctx, cancel := context.WithTimeout(b.Context(), 10*time.Minute)
	defer cancel()
	addr, err := netapi.ParseAddress("tcp", net.JoinHostPort(target, "19991"))
	if err != nil {
		b.Fatal(err)
	}
	conn, err := proxy.Conn(ctx, addr)
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Minute)); err != nil {
		b.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x5a}, 1<<20)
	received := make([]byte, len(payload))
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := sstpTCPEcho(conn, payload, received); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSoftEtherSSTPUDPEcho(b *testing.B) {
	proxy, target := dialSoftEtherProxy(b)
	ctx, cancel := context.WithTimeout(b.Context(), 10*time.Minute)
	defer cancel()
	addr, err := netapi.ParseAddress("udp", net.JoinHostPort(target, "19992"))
	if err != nil {
		b.Fatal(err)
	}
	conn, err := proxy.PacketConn(ctx, addr)
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Minute)); err != nil {
		b.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x5a}, 1200)
	received := make([]byte, 1500)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := sstpUDPEcho(conn, addr, payload, received); err != nil {
			b.Fatal(err)
		}
	}
}

func dialSoftEtherProxy(tb testing.TB) (netapi.Proxy, string) {
	tb.Helper()
	target := os.Getenv("SSTP_TEST_ECHO_IP")
	if net.ParseIP(target) == nil {
		tb.Skip("set SSTP_TEST_ECHO_IP to run the SoftEther SSTP data-plane test")
	}
	port, err := strconv.Atoi(os.Getenv("SSTP_TEST_PORT"))
	if err != nil || port < 1 || port > 65535 {
		tb.Fatalf("invalid SSTP_TEST_PORT %q", os.Getenv("SSTP_TEST_PORT"))
	}
	proxy, err := NewOutbound(contractnode.SSTP{
		Gateway:            net.JoinHostPort(os.Getenv("SSTP_TEST_GATEWAY"), strconv.Itoa(port)),
		Username:           "alice",
		Password:           "test-password",
		InsecureSkipVerify: true,
	}, nil)
	if err != nil {
		tb.Fatalf("open SSTP outbound: %v", err)
	}
	tb.Cleanup(func() { _ = proxy.Close() })
	return proxy, target
}

func sstpTCPEcho(conn net.Conn, payload, received []byte) error {
	if len(payload) != len(received) {
		return fmt.Errorf("TCP echo buffers differ: sent %d bytes, receive buffer %d", len(payload), len(received))
	}
	readDone := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(conn, received)
		readDone <- err
	}()
	for sent := 0; sent < len(payload); {
		n, err := conn.Write(payload[sent:])
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		sent += n
	}
	if err := <-readDone; err != nil {
		return err
	}
	if !bytes.Equal(received, payload) {
		return errors.New("TCP echo payload mismatch")
	}
	return nil
}

func sstpUDPEcho(conn net.PacketConn, addr net.Addr, payload, received []byte) error {
	if _, err := conn.WriteTo(payload, addr); err != nil {
		return err
	}
	n, _, err := conn.ReadFrom(received)
	if err != nil {
		return err
	}
	if !bytes.Equal(received[:n], payload) {
		return errors.New("UDP echo payload mismatch")
	}
	return nil
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
