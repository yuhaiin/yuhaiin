package l2tp

import (
	"errors"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"testing"
)

func TestBackgroundProbeDoesNotWaitForReauthentication(t *testing.T) {
	r := &reconnectingClient{changed: make(chan struct{})}
	if s := r.NodeRuntimeStatus(); s.State != "reconnecting" {
		t.Fatal(s)
	}
	if _, err := r.available(netapi.WithBackgroundProbe(t.Context())); !errors.Is(err, netapi.ErrBackgroundProbeUnavailable) {
		t.Fatal(err)
	}
	if s := new(Client).NodeRuntimeStatus(); s.State != "unknown" {
		t.Fatal("construction inferred handshake", s)
	}
	r.stopped = true
	if s := r.NodeRuntimeStatus(); s.State != "closed" {
		t.Fatal(s)
	}
}
