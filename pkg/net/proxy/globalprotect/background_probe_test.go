package globalprotect

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

func TestBackgroundProbeCannotDemandIdleVPNReconnect(t *testing.T) {
	c := newReconnectingClient(Config{}, nil, nil)
	defer c.Close()
	c.waitingForDemand = true
	if s := c.NodeRuntimeStatus(); s.State != "idle" {
		t.Fatal(s)
	}
	if _, err := c.current(netapi.WithBackgroundProbe(t.Context())); !errors.Is(err, netapi.ErrBackgroundProbeUnavailable) {
		t.Fatal(err)
	}
	if len(c.demand) != 0 {
		t.Fatal("periodic probe woke VPN login")
	}
	// A normal application request still signals the existing demand mechanism.
	ctx, cancel := context.WithTimeout(t.Context(), time.Millisecond)
	defer cancel()
	if _, err := c.current(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if len(c.demand) != 1 {
		t.Fatal("ordinary request no longer wakes demand")
	}
}
