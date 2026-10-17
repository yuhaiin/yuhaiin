package fortinet

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/internal/testutil/leaktest"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit/vlog"
)

func TestLoginContextResponseBodyReadErrors(t *testing.T) {
	for _, stage := range []string{"login", "config"} {
		t.Run(stage, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if stage == "config" && r.URL.Path == PathLoginCheck {
					http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "test-session", Path: "/"})
					_, _ = io.WriteString(w, "ret=1")
					return
				}
				// End the response before its declared body is complete.
				w.Header().Set("Content-Length", "1")
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
			}))
			t.Cleanup(server.Close)
			hc := server.Client()
			hc.Jar, _ = cookiejar.New(nil)
			_, _, err := LoginContext(t.Context(), hc, server.URL, "alice", "", "", nil)
			if !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("LoginContext() error = %v, want io.ErrUnexpectedEOF", err)
			}
		})
	}
}

func TestLoginContextCancelsResponseBody(t *testing.T) {
	leaktest.VerifyNoGoroutineLeaks(t)
	started := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
	}))
	t.Cleanup(server.Close)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, _, err := LoginContext(ctx, server.Client(), server.URL, "alice", "", "", nil)
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("login response headers were not received")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("LoginContext() error = %v, want context.Canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("reading the login response did not stop after cancellation")
	}
}

func TestRunClientContextCancellationClosesTransportAndTUN(t *testing.T) {
	leaktest.VerifyNoGoroutineLeaks(t)
	clientConn, peerConn := net.Pipe()
	tun := &lifecycleTUN{closed: make(chan struct{})}
	frameSeen := make(chan struct{})
	peerDone := make(chan struct{})
	var frameOnce sync.Once
	go func() {
		defer close(peerDone)
		buf := make([]byte, 4096)
		for {
			n, err := peerConn.Read(buf)
			if n > 0 {
				frameOnce.Do(func() { close(frameSeen) })
			}
			if err != nil {
				return
			}
		}
	}()
	defer peerConn.Close()

	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() {
		_, err := RunClientContext(ctx, clientConn, Config{}, tun, vlog.Discard())
		result <- err
	}()

	select {
	case <-frameSeen:
	case <-time.After(3 * time.Second):
		t.Fatal("PPP setup did not start")
	}
	cancel()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("RunClientContext() error = %v, want context.Canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("PPP setup did not return after cancellation")
	}

	select {
	case <-tun.closed:
	case <-time.After(3 * time.Second):
		t.Fatal("TUN remained open after PPP setup cancellation")
	}
	select {
	case <-peerDone:
	case <-time.After(3 * time.Second):
		t.Fatal("peer connection remained open after PPP setup cancellation")
	}
}

func TestPPPLinkWaitContextCancellationDoesNotLeakWaiter(t *testing.T) {
	leaktest.VerifyNoGoroutineLeaks(t)
	conn, peer := net.Pipe()
	tun := &lifecycleTUN{closed: make(chan struct{})}
	link := &pppLink{conn: conn, tun: tun, done: make(chan struct{})}
	t.Cleanup(func() { _ = peer.Close() })

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := link.WaitContext(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("WaitContext() error = %v, want context.Canceled", err)
	}
	select {
	case <-link.done:
		t.Fatal("canceling WaitContext closed the session")
	default:
	}

	if err := link.Close(); err != nil {
		t.Fatal(err)
	}
	if err := link.WaitContext(t.Context()); err != nil {
		t.Fatalf("WaitContext() after Close = %v, want nil", err)
	}
	select {
	case <-tun.closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not close the TUN")
	}
	if _, err := peer.Read(make([]byte, 1)); err == nil {
		t.Fatal("Close left the peer connection open")
	}
}

type lifecycleTUN struct {
	closed chan struct{}
	once   sync.Once
}

func (t *lifecycleTUN) Read([]byte) (int, error) {
	<-t.closed
	return 0, net.ErrClosed
}

func (t *lifecycleTUN) Write(p []byte) (int, error) { return len(p), nil }

func (t *lifecycleTUN) Close() error {
	t.once.Do(func() { close(t.closed) })
	return nil
}
