package fortinet

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	ifortinet "github.com/Asutorufa/yuhaiin/pkg/net/proxy/fortinet/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/internal/testutil/leaktest"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit/vlog"
)

func TestDialContextCancelsBlockedLogin(t *testing.T) {
	leaktest.VerifyNoGoroutineLeaks(t)
	started := make(chan struct{})
	requestDone := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != ifortinet.PathLoginCheck {
			http.NotFound(w, r)
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		close(started)
		select {
		case <-r.Context().Done():
			close(requestDone)
		case <-release:
		}
	}))
	t.Cleanup(func() {
		close(release)
		server.Close()
	})

	_, portText, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() {
		_, _, err := Dial(ctx, Config{
			Server:   "127.0.0.1",
			Port:     port,
			Username: "alice",
			Insecure: true,
		})
		result <- err
	}()

	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("login request did not reach the test server")
	}
	cancel()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Dial() error = %v, want context.Canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Dial() did not return after cancellation")
	}

	select {
	case <-requestDone:
	case <-time.After(3 * time.Second):
		t.Fatal("server-side login handler did not observe cancellation")
	}
}

func TestDialTLSPathContextCancelsHandshake(t *testing.T) {
	leaktest.VerifyNoGoroutineLeaks(t)
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { _ = serverConn.Close() })
	wrote := make(chan struct{})
	readDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, serverConn)
		close(readDone)
	}()

	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() {
		_, err := dialTLSPath(ctx, "localhost:443", "", ifortinet.Config{}, &tls.Config{
			ServerName:         "localhost",
			InsecureSkipVerify: true, //nolint:gosec // handshake cancellation test has no server certificate.
		}, nil, vlog.Discard(), func(context.Context, string, string) (net.Conn, error) {
			return &observedWriteConn{Conn: clientConn, wrote: wrote}, nil
		})
		result <- err
	}()

	select {
	case <-wrote:
	case <-time.After(3 * time.Second):
		t.Fatal("TLS client did not send its handshake")
	}
	cancel()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("dialTLSPath() error = %v, want context.Canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("TLS handshake did not stop after cancellation")
	}

	select {
	case <-readDone:
	case <-time.After(3 * time.Second):
		t.Fatal("peer connection remained open after cancellation")
	}
}

func TestDialDTLSChannelContextCancelsHandshake(t *testing.T) {
	leaktest.VerifyNoGoroutineLeaks(t)
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { _ = serverConn.Close() })
	wrote := make(chan struct{})
	readDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, serverConn)
		close(readDone)
	}()

	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() {
		_, err := dialDTLSChannel(ctx, "localhost:443", "cookie", &tls.Config{
			ServerName:         "localhost",
			InsecureSkipVerify: true, //nolint:gosec // handshake cancellation test has no server certificate.
		}, func(context.Context, string, string) (net.Conn, error) {
			return &observedWriteConn{Conn: clientConn, wrote: wrote}, nil
		})
		result <- err
	}()

	select {
	case <-wrote:
	case <-time.After(3 * time.Second):
		t.Fatal("DTLS client did not send its handshake")
	}
	cancel()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("dialDTLSChannel() error = %v, want context.Canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("DTLS handshake did not stop after cancellation")
	}

	select {
	case <-readDone:
	case <-time.After(3 * time.Second):
		t.Fatal("peer connection remained open after DTLS cancellation")
	}
}

type observedWriteConn struct {
	net.Conn
	wrote chan struct{}
	once  sync.Once
}

func (c *observedWriteConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.once.Do(func() { close(c.wrote) })
	}
	return n, err
}
