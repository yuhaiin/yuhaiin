package helper

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection/pf"
)

// Backend is the macOS protection backend used by the Yuhaiin core: a
// client of the protection service. Everything that changes the packet
// filter happens in the service, so the core's lifetime does not matter.
type Backend struct {
	client *Client

	mu  sync.Mutex
	gid int
}

// NewBackend returns this platform's protection backend.
func NewBackend() protection.Backend {
	if !Supported {
		return protection.Unsupported{}
	}
	return &Backend{client: NewClient("api")}
}

// Status asks the service. The service only runs while protection is on, so
// when it does not answer and the saved state says protection is off, that
// is the normal disabled state, not an error.
func (b *Backend) Status(ctx context.Context) (sysnet.ProtectionStatus, error) {
	st, err := b.client.Call(ctx, OpStatus, nil)
	if err == nil {
		return st, nil
	}
	if !serviceDown(err) {
		return st, err
	}
	saved, _, stateErr := LoadState(StateFile)
	if stateErr != nil || saved.Enabled {
		// Requested but the service is gone: a real problem.
		return st, err
	}
	off := OfflineStatus(saved)
	off.OwnTraffic.GroupID = b.groupID(ctx)
	return off, nil
}

// groupID caches the socket group's gid, read without the service.
func (b *Backend) groupID(ctx context.Context) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.gid == 0 {
		b.gid = LookupGroupID(ctx)
	}
	return b.gid
}

// OfflineStatus is the status while the service is stopped because
// protection is off.
func OfflineStatus(saved State) sysnet.ProtectionStatus {
	st := Describe(pf.Inspection{}, saved, nil)
	st.Service = "stopped"
	if st.Desired.Enabled {
		st.State = sysnet.ProtectionError
	} else {
		st.State = sysnet.ProtectionDisabled
	}
	return st
}

// Enable starts the service, which only runs while protection is on, and
// sends the policy. If the service was just stopping itself (protection was
// turned off a moment ago), it is started again and the request repeated.
func (b *Backend) Enable(ctx context.Context, p protection.Policy) error {
	var err error
	for range 2 {
		if _, statusErr := b.client.Call(ctx, OpStatus, nil); statusErr != nil || DaemonDisabled(ctx) {
			if !serviceDown(statusErr) && statusErr != nil {
				return statusErr
			}
			if startErr := StartDaemon(ctx); startErr != nil {
				return errors.Join(statusErr, startErr)
			}
		}
		if _, err = b.client.Call(ctx, OpEnable, &p); err == nil || !serviceDown(err) {
			return err
		}
	}
	return err
}

func serviceDown(err error) bool {
	if err == nil {
		return false
	}
	problem, ok := errors.AsType[*protection.ProblemError](err)
	return ok && (problem.Problem.Code == sysnet.ProblemServiceDown || problem.Problem.Code == sysnet.ProblemServiceMissing)
}

func (b *Backend) Update(ctx context.Context, p protection.Policy) error {
	_, err := b.client.Call(ctx, OpUpdate, &p)
	return err
}

func (b *Backend) Disable(ctx context.Context) error {
	_, err := b.client.Call(ctx, OpDisable, nil)
	if !serviceDown(err) {
		return err
	}
	if !savedEnabled() {
		return nil // already off; the service stopped itself
	}
	// Protection is on but the service does not run: start it to disable.
	if startErr := StartDaemon(ctx); startErr != nil {
		return errors.Join(err, startErr, errors.New("run: sudo yuhaiin protection disable --recovery"))
	}
	_, err = b.client.Call(ctx, OpDisable, nil)
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
	// After an update the core starts from the new binary: bring the
	// protection service to the same build first.
	EnsureCurrent(ctx)
	c := NewClient("api")
	defer c.Close()
	for {
		status, err := c.Call(ctx, OpStatus, nil)
		if err == nil {
			joinSocketGroup(status.OwnTraffic.GroupID)
			return
		}
		// The service runs only while protection is on; the group exists
		// from installation, so join it directly. Yuhaiin's connections
		// then already pass when protection is enabled later.
		if gid := LookupGroupID(ctx); gid > 0 {
			joinSocketGroup(gid)
		}
		// At boot both LaunchDaemons start together: wait for a service
		// launchd has loaded, never for a missing or stopped one (after
		// emergency recovery).
		if !DaemonLoaded(ctx) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// Rules reads the packet filter rules directly (the core runs as root). It
// only reads, so it works whether or not the protection service runs, and
// also shows the forwarding rules the core itself loads.
func (b *Backend) Rules(ctx context.Context) sysnet.ProtectionRules {
	return pf.NewEngine(StateDir).Snapshot(ctx)
}
