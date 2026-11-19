package protection

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/policy"
)

// Inputs is what the System Network Manager contributes to the policy. It is
// derived from the effective routing configuration, never from the
// operating system routing table, so the default route of a physical
// interface can never become a bypass.
type Inputs struct {
	// Bypass are destinations the user explicitly sends outside Yuhaiin.
	Bypass []netip.Prefix
	// Ignored explains configured bypass entries that were not allowed.
	Ignored []string
	// Tunnels are the running Yuhaiin TUNs.
	Tunnels []Tunnel
}

// Controller keeps a Backend in sync with Yuhaiin's routing state.
//
// Updates are serialized: one goroutine applies them, always from the latest
// inputs, so an older update can never overwrite a newer one. Bursts of
// network events coalesce into one update, and an unchanged policy is not
// sent again.
type Controller struct {
	backend Backend
	poll    time.Duration
	now     func() time.Time

	mu         sync.Mutex
	inputs     Inputs
	haveInputs bool
	status     sysnet.ProtectionStatus
	statusOK   bool
	syncErr    error
	sent       string
	session    uint64
	blocked    uint64
	blockedAt  *int64
	closed     bool

	// opMu serializes every write to the backend.
	opMu sync.Mutex
	wake chan struct{}
	done chan struct{}
	wg   sync.WaitGroup
}

// NewController starts keeping backend in sync. Status is polled every few
// seconds so the reported state follows the operating system, not Yuhaiin's
// last request.
func NewController(backend Backend) *Controller {
	c := newController(backend, 5*time.Second)
	c.start()
	return c
}

func newController(backend Backend, poll time.Duration) *Controller {
	return &Controller{backend: backend, poll: poll, now: time.Now, wake: make(chan struct{}, 1), done: make(chan struct{})}
}

func (c *Controller) start() {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		ticker := time.NewTicker(c.poll)
		defer ticker.Stop()
		c.sync("start")
		for {
			select {
			case <-c.done:
				return
			case <-c.wake:
				c.sync("inputs changed")
			case <-ticker.C:
				c.sync("poll")
			}
		}
	}()
}

// SetInputs records the latest routing state and schedules a sync.
func (c *Controller) SetInputs(in Inputs) {
	c.mu.Lock()
	c.inputs = Inputs{Bypass: slices.Clone(in.Bypass), Ignored: slices.Clone(in.Ignored), Tunnels: slices.Clone(in.Tunnels)}
	c.haveInputs = true
	c.mu.Unlock()
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// policyLocked builds the policy for the current inputs. c.mu is held.
func (c *Controller) policyLocked(settings sysnet.ProtectionSettings, status sysnet.ProtectionStatus) Policy {
	own := false
	if p, ok := c.backend.(ProcessPreparer); ok {
		own, _ = p.PrepareProcess(status)
	}
	return Policy{
		Mode: sysnet.ProtectionModeStandard, StartAtBoot: settings.StartAtBoot,
		PrivateNetworks: policy.PrivateNetworks(), BypassNetworks: c.inputs.Bypass,
		Tunnels: c.inputs.Tunnels, OwnTraffic: own,
	}.Normalize()
}

func (c *Controller) backendSession() uint64 {
	if s, ok := c.backend.(Sessioned); ok {
		return s.Session()
	}
	return 0
}

// sync reads the backend state and, while protection is requested, sends
// the policy if it changed or the backend lost it.
func (c *Controller) sync(reason string) {
	c.opMu.Lock()
	defer c.opMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	status, err := c.backend.Status(ctx)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.record(status, err)
	if err != nil || !status.Desired.Enabled {
		c.sent, c.syncErr = "", nil
		return
	}
	p := c.policyLocked(status.Desired, status)
	fp, session := p.Fingerprint(), c.backendSession()
	if fp == c.sent && session == c.session && c.syncErr == nil {
		return
	}
	c.mu.Unlock()
	err = c.backend.Update(ctx, p)
	after, statusErr := c.backend.Status(ctx)
	c.mu.Lock()
	if c.closed {
		return
	}
	c.syncErr = err
	if err != nil {
		log.Error("network protection policy update failed; the previous rules stay in force", "reason", reason, "err", err)
	} else {
		c.sent, c.session = fp, session
	}
	c.record(after, statusErr)
}

// record stores a backend status and tracks when blocking was last seen.
func (c *Controller) record(status sysnet.ProtectionStatus, err error) {
	if err != nil {
		c.statusOK = false
		c.status = errorStatus(err)
		return
	}
	if status.Blocked != nil {
		now := c.now().Unix()
		if status.Blocked.Packets > c.blocked && c.statusOK {
			c.blockedAt = &now
		}
		c.blocked = status.Blocked.Packets
		if status.Blocked.LastAt == nil && c.blockedAt != nil {
			at := *c.blockedAt
			status.Blocked.LastAt = &at
		}
	}
	c.status, c.statusOK = status, true
}

func errorStatus(err error) sysnet.ProtectionStatus {
	s := UnsupportedStatus()
	s.State, s.Supported, s.Error = sysnet.ProtectionError, true, err.Error()
	var problem *ProblemError
	if errors.As(err, &problem) {
		s.Problems = []sysnet.ProtectionProblem{problem.Problem}
		if problem.Problem.Code == sysnet.ProblemServiceMissing {
			s.Service = "not_installed"
		} else {
			s.Service = "unreachable"
		}
	} else {
		s.Service = "unreachable"
	}
	return s
}

// ProblemError carries a structured problem through error returns.
type ProblemError struct{ Problem sysnet.ProtectionProblem }

func (e *ProblemError) Error() string {
	if e.Problem.Hint == "" {
		return e.Problem.Message
	}
	return e.Problem.Message + ". " + e.Problem.Hint
}

// Problem returns an error with a code, message and suggested fix.
func Problem(code, message, hint string) error {
	return &ProblemError{Problem: sysnet.ProtectionProblem{Code: code, Message: message, Hint: hint}}
}

// Status returns the current state, read from the backend now.
func (c *Controller) Status(ctx context.Context) sysnet.ProtectionStatus {
	status, err := c.backend.Status(ctx)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.record(status, err)
	return c.decorateLocked()
}

// decorateLocked adds what only Yuhaiin knows: problems of its inputs and of
// the last policy update. c.mu is held.
func (c *Controller) decorateLocked() sysnet.ProtectionStatus {
	s := c.status
	s.Problems = slices.Clone(s.Problems)
	if !c.statusOK {
		return s
	}
	if c.syncErr != nil && s.Desired.Enabled {
		s.Problems = append(s.Problems, problemOf(c.syncErr, sysnet.ProblemPolicySync, "The previous protection rules stay in force"))
		if s.State == sysnet.ProtectionProtected {
			s.State = sysnet.ProtectionDegraded
		}
	}
	if s.Effective && c.haveInputs && len(c.inputs.Tunnels) == 0 {
		s.Problems = append(s.Problems, sysnet.ProtectionProblem{Code: sysnet.ProblemTunnelMissing,
			Message: "No Yuhaiin TUN is running, so all Internet traffic of other applications is blocked",
			Hint:    "Start a TUN inbound and route traffic to it in System Network, or disable the kill switch"})
	}
	for _, reason := range c.inputs.Ignored {
		if s.Desired.Enabled {
			s.Problems = append(s.Problems, sysnet.ProtectionProblem{Code: sysnet.ProblemBypassIgnored, Message: reason})
		}
	}
	return s
}

func problemOf(err error, code, hint string) sysnet.ProtectionProblem {
	var problem *ProblemError
	if errors.As(err, &problem) {
		return problem.Problem
	}
	return sysnet.ProtectionProblem{Code: code, Message: err.Error(), Hint: hint}
}

// Save applies the user's settings. Enabling sends the current policy at
// once, so the response reports whether protection really took effect.
func (c *Controller) Save(ctx context.Context, settings sysnet.ProtectionSettings) (sysnet.ProtectionStatus, error) {
	c.opMu.Lock()
	defer c.opMu.Unlock()
	status, err := c.backend.Status(ctx)
	if err != nil {
		c.mu.Lock()
		c.record(status, err)
		c.mu.Unlock()
		return sysnet.ProtectionStatus{}, err
	}
	if !status.Supported {
		return sysnet.ProtectionStatus{}, ErrUnsupported
	}
	if settings.Enabled {
		c.mu.Lock()
		p := c.policyLocked(settings, status)
		c.mu.Unlock()
		if err := c.backend.Enable(ctx, p); err != nil {
			c.mu.Lock()
			c.syncErr = err
			c.mu.Unlock()
			return c.Status(ctx), fmt.Errorf("enable network protection: %w", err)
		}
		c.mu.Lock()
		c.sent, c.session, c.syncErr = p.Fingerprint(), c.backendSession(), nil
		c.mu.Unlock()
	} else {
		if err := c.backend.Disable(ctx); err != nil {
			return c.Status(ctx), fmt.Errorf("disable network protection: %w", err)
		}
		c.mu.Lock()
		c.sent, c.syncErr = "", nil
		c.mu.Unlock()
	}
	return c.Status(ctx), nil
}

// Close stops syncing and closes the backend connection. Protection rules
// are deliberately left in force: a stopping or crashing Yuhaiin must not
// open the network.
func (c *Controller) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()
	close(c.done)
	c.wg.Wait()
	return c.backend.Close()
}
