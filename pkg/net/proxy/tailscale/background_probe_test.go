package tailscale

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

func TestBackgroundProbeCannotInitializeLazyTailnetIdentity(t *testing.T) {
	p, err := New(Config{AuthKey: "local-test-placeholder", Hostname: "unused", ControlURL: "http://127.0.0.1:1"}, netapi.NewErrProxy(errors.New("upstream must stay untouched")))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	node := p.(*Tailscale)
	if s := node.NodeRuntimeStatus(); s.State != "idle" {
		t.Fatal(s)
	}
	a, _ := netapi.ParseAddress("tcp", "192.0.2.1:443")
	if _, err := p.Conn(netapi.WithBackgroundProbe(t.Context()), a); !errors.Is(err, netapi.ErrBackgroundProbeUnavailable) {
		t.Fatal(err)
	}
	if node.tsnet != nil || node.stateDir != "" {
		t.Fatal("periodic probe created a Tailnet identity/client")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := p.Conn(ctx, a); !errors.Is(err, context.Canceled) {
		t.Fatal("manual path changed", err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if s := node.NodeRuntimeStatus(); s.State != "closed" {
		t.Fatal(s)
	}
}

func TestBackgroundStatusAndProbeCannotWaitBehindTailnetInitialization(t *testing.T) {
	node := &Tailscale{}
	node.mu.Lock()
	done := make(chan error, 1)
	go func() {
		if s := node.NodeRuntimeStatus(); s.State != "connecting" {
			done <- errors.New("busy init not reported")
			return
		}
		_, err := node.init(netapi.WithBackgroundProbe(t.Context()))
		done <- err
	}()
	select {
	case err := <-done:
		node.mu.Unlock()
		if !errors.Is(err, netapi.ErrBackgroundProbeUnavailable) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		node.mu.Unlock()
		t.Fatal("background observation waited on expensive login")
	}
}
