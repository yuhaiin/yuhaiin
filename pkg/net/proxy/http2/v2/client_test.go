package http2

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type addressDialer struct {
	netapi.Proxy
	addr  string
	calls atomic.Int32
}

func (d *addressDialer) Conn(ctx context.Context, _ netapi.Address) (net.Conn, error) {
	d.calls.Add(1)
	return (&net.Dialer{}).DialContext(ctx, "tcp", d.addr)
}

func http2TestClient(t *testing.T, limit int, handler http.Handler) (*Client, *addressDialer) {
	t.Helper()
	s := httptest.NewUnstartedServer(handler)
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	s.Config.Protocols = protocols
	s.Config.HTTP2 = &http.HTTP2Config{MaxConcurrentStreams: limit}
	s.Start()
	t.Cleanup(s.Close)
	d := &addressDialer{addr: s.Listener.Addr().String()}
	p, err := NewClient(Config{}, d)
	if err != nil {
		t.Fatal(err)
	}
	c := p.(*Client)
	t.Cleanup(func() { c.Close() })
	return c, d
}

func echoHTTP2(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_ = http.NewResponseController(w).Flush()
	_, _ = io.Copy(&flusher{w: w}, r.Body)
}

func assertTunnelEcho(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = conn.Write([]byte("alive")) }()
	var data [5]byte
	if _, err := io.ReadFull(conn, data[:]); err != nil {
		t.Fatal(err)
	}
	if string(data[:]) != "alive" {
		t.Fatalf("echo=%q", data)
	}
}

func TestPeerStreamLimitDoesNotCloseActiveTunnel(t *testing.T) {
	c, d := http2TestClient(t, 1, http.HandlerFunc(echoHTTP2))
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	first, err := c.Conn(ctx, netapi.EmptyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := c.Conn(ctx, netapi.EmptyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if d.calls.Load() != 2 {
		t.Fatalf("dials=%d, want separate connection at peer limit", d.calls.Load())
	}
	assertTunnelEcho(t, first)
	assertTunnelEcho(t, second)
}

func TestCanceledStreamPreservesOtherTunnels(t *testing.T) {
	var requests atomic.Int32
	c, _ := http2TestClient(t, 100, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 2 {
			<-r.Context().Done()
			return
		}
		echoHTTP2(w, r)
	}))
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	first, err := c.Conn(ctx, netapi.EmptyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	cancel() // Successful tunnels must outlive their dialing context.
	failingCtx, failingCancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer failingCancel()
	if _, err := c.Conn(failingCtx, netapi.EmptyAddr); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error=%v", err)
	}
	assertTunnelEcho(t, first)
}

func TestConnectRejectsHTTPError(t *testing.T) {
	c, _ := http2TestClient(t, 100, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "rejected", http.StatusForbidden) }))
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if conn, err := c.Conn(ctx, netapi.EmptyAddr); err == nil {
		conn.Close()
		t.Fatal("403 accepted as tunnel")
	}
}
