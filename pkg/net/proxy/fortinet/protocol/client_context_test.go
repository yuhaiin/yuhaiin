package fortinet

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/internal/testutil/leaktest"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit/vlog"
)

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
