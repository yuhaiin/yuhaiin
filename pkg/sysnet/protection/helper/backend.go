package helper

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection"
)

// Backend is the macOS protection backend used by the Yuhaiin core: a
// client of the protection service. Everything that changes the packet
// filter happens in the service, so the core's lifetime does not matter.
type Backend struct {
	client *Client
}

// NewBackend returns this platform's protection backend.
func NewBackend() protection.Backend {
	if !Supported {
		return protection.Unsupported{}
	}
	return &Backend{client: NewClient("api")}
}

func (b *Backend) Status(ctx context.Context) (sysnet.ProtectionStatus, error) {
	return b.client.Call(ctx, OpStatus, nil)
}

func (b *Backend) Enable(ctx context.Context, p protection.Policy) error {
	if _, err := b.client.Call(ctx, OpStatus, nil); err != nil {
		// Start (or, after an upgrade, install) the service on demand.
		var problem *protection.ProblemError
		if !errors.As(err, &problem) || problem.Problem.Code == sysnet.ProblemPermission {
			return err
		}
		if startErr := EnsureDaemon(ctx); startErr != nil {
			return errors.Join(err, startErr)
		}
	}
	_, err := b.client.Call(ctx, OpEnable, &p)
	return err
}

func (b *Backend) Update(ctx context.Context, p protection.Policy) error {
	_, err := b.client.Call(ctx, OpUpdate, &p)
	return err
}

func (b *Backend) Disable(ctx context.Context) error {
	_, err := b.client.Call(ctx, OpDisable, nil)
	return err
}

func (b *Backend) Close() error    { return b.client.Close() }
func (b *Backend) Session() uint64 { return b.client.Session() }

// PrepareProcess puts the process into the socket group the service
// reports, so its new sockets pass the kill switch.
func (b *Backend) PrepareProcess(status sysnet.ProtectionStatus) (bool, string) {
	return joinSocketGroup(status.OwnTraffic.GroupID)
}

// PrepareStartup joins the socket group before Yuhaiin opens any socket,
// so connections made at startup already pass the kill switch. It does
// nothing when the service is not reachable.
func PrepareStartup(ctx context.Context) {
	if !Supported {
		return
	}
	c := NewClient("api")
	defer c.Close()
	for {
		status, err := c.Call(ctx, OpStatus, nil)
		if err == nil {
			joinSocketGroup(status.OwnTraffic.GroupID)
			return
		}
		// At boot both LaunchDaemons start together: wait briefly for an
		// installed service, never for a missing one.
		if _, statErr := os.Stat(PlistPath); statErr != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(200 * time.Millisecond):
		}
	}
}
