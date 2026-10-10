package softether

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/softether/native"
)

func TestReconnectFailsClosedAndStopsAfterAuthRejection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	r := &reconnectingClient{ctx: ctx, cancel: cancel, changed: make(chan struct{})}
	timed, cancelTimed := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelTimed()
	if _, err := r.available(timed); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline while reconnecting, got %v", err)
	}
	r.mu.Lock()
	r.failure = native.ErrAuth
	r.notifyLocked()
	r.mu.Unlock()
	if _, err := r.available(context.Background()); !errors.Is(err, native.ErrAuth) {
		t.Fatalf("expected terminal authentication error, got %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.available(context.Background()); err == nil {
		t.Fatal("client unexpectedly usable after close")
	}
}
