//go:build fortinet_interop

package fortinet

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/internal/testutil"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/internal/testutil/leaktest"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit"
	session "github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit/session"
)

func TestFortinetGatewayUDPAndReconnectAfterClose(t *testing.T) {
	if !fortinetInteropConfigured() {
		t.Skip("set FORTINET_TEST_GATEWAY, FORTINET_TEST_USERNAME, FORTINET_TEST_PASSWORD, FORTINET_TEST_ECHO_IP, and FORTINET_TEST_ECHO_UDP_PORT")
	}
	leaktest.VerifyNoGoroutineLeaks(t)
	echoIP, echoPort := fortinetInteropEcho(t)
	want := []byte("FortiOS SSL VPN PPP UDP echo")

	for range 2 {
		tun, unregister, sess, result := dialFortinetInterop(t)
		if result.AssignedIP.To4() == nil {
			t.Fatalf("assigned IP = %v, want IPv4", result.AssignedIP)
		}

		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		packet := testutil.IPv4UDP(result.AssignedIP, echoIP, 40123, echoPort, want)
		if err := tun.Send(packet); err != nil {
			cancel()
			t.Fatalf("send UDP packet into Fortinet tunnel: %v", err)
		}
		reply, err := tun.Receive(ctx)
		cancel()
		if err != nil {
			t.Fatalf("receive UDP echo through Fortinet tunnel: %v", err)
		}
		got, err := testutil.IPv4UDPData(reply)
		if err != nil {
			t.Fatalf("parse Fortinet tunnel UDP reply: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("UDP echo = %q, want %q", got, want)
		}

		if err := sess.Close(); err != nil {
			t.Fatalf("close Fortinet session: %v", err)
		}
		waitCtx, waitCancel := context.WithTimeout(t.Context(), 5*time.Second)
		if err := sess.Wait(waitCtx); err != nil {
			waitCancel()
			t.Fatalf("Fortinet session did not stop after Close: %v", err)
		}
		waitCancel()
		unregister()
	}
}

func fortinetInteropConfigured() bool {
	return os.Getenv("FORTINET_TEST_GATEWAY") != "" &&
		os.Getenv("FORTINET_TEST_USERNAME") != "" &&
		os.Getenv("FORTINET_TEST_PASSWORD") != "" &&
		os.Getenv("FORTINET_TEST_ECHO_IP") != "" &&
		os.Getenv("FORTINET_TEST_ECHO_UDP_PORT") != ""
}

func fortinetInteropEcho(tb testing.TB) (net.IP, uint16) {
	tb.Helper()
	ip := net.ParseIP(os.Getenv("FORTINET_TEST_ECHO_IP"))
	if ip == nil || ip.To4() == nil {
		tb.Fatalf("FORTINET_TEST_ECHO_IP must be an IPv4 address, got %q", os.Getenv("FORTINET_TEST_ECHO_IP"))
	}
	port, err := strconv.Atoi(os.Getenv("FORTINET_TEST_ECHO_UDP_PORT"))
	if err != nil || port < 1 || port > 65535 {
		tb.Fatalf("FORTINET_TEST_ECHO_UDP_PORT must be in 1..65535, got %q", os.Getenv("FORTINET_TEST_ECHO_UDP_PORT"))
	}
	return ip, uint16(port)
}

func dialFortinetInterop(tb testing.TB) (*testutil.VirtualTUN, func(), *Session, session.Result) {
	tb.Helper()
	host, port, err := parseFortinetTestGateway(os.Getenv("FORTINET_TEST_GATEWAY"))
	if err != nil {
		tb.Fatal(err)
	}

	tunName := fmt.Sprintf("fortinet-test-%d", time.Now().UnixNano())
	tun, unregister, err := testutil.NewVirtualTUN(tunName)
	if err != nil {
		tb.Fatal(err)
	}
	cfg := Config{
		Server:     host,
		Port:       port,
		Username:   os.Getenv("FORTINET_TEST_USERNAME"),
		Password:   os.Getenv("FORTINET_TEST_PASSWORD"),
		Realm:      os.Getenv("FORTINET_TEST_REALM"),
		Token:      os.Getenv("FORTINET_TEST_TOKEN"),
		TOTPSecret: os.Getenv("FORTINET_TEST_TOTP_SECRET"),
		TUNName:    tunName,
		Insecure:   os.Getenv("FORTINET_TEST_INSECURE") == "true",
		NoDTLS:     os.Getenv("FORTINET_TEST_DISABLE_DTLS") == "true",
	}
	if caPath := os.Getenv("FORTINET_TEST_CA_CERT"); caPath != "" {
		pem, err := os.ReadFile(caPath)
		if err != nil {
			unregister()
			tb.Fatalf("read Fortinet test CA certificate: %v", err)
		}
		cfg.RootCAs = x509.NewCertPool()
		if !cfg.RootCAs.AppendCertsFromPEM(pem) {
			unregister()
			tb.Fatalf("FORTINET_TEST_CA_CERT %q contains no certificates", caPath)
		}
	}

	ctx, cancel := context.WithTimeout(tb.Context(), 30*time.Second)
	sess, result, err := Dial(ctx, cfg)
	cancel()
	if err != nil {
		unregister()
		tb.Fatalf("dial FortiOS SSL VPN: %v", err)
	}
	tb.Cleanup(func() {
		_ = sess.Close()
		unregister()
	})
	return tun, unregister, sess, result
}

func parseFortinetTestGateway(gateway string) (string, int, error) {
	host, port, err := vpnkit.ParseGateway(gateway, defaultPort)
	if err != nil {
		return "", 0, fmt.Errorf("parse FORTINET_TEST_GATEWAY: %w", err)
	}
	return host, port, nil
}
