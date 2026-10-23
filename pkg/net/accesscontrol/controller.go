package accesscontrol

import (
	"context"
	"strconv"
	"sync"
	"sync/atomic"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/access"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

const maxSessions = 65536
const maxTargets = 131072
const maxSessionTargets = 1024

type Controller struct {
	applyMu                           sync.Mutex
	mu                                sync.Mutex
	sessions                          map[*Session]struct{}
	active                            atomic.Pointer[Prepared]
	closed                            atomic.Bool
	denied, revoked, capacityRejected atomic.Uint64
	targets                           atomic.Int64
	evaluations                       sync.Pool
}

func New() *Controller {
	c := &Controller{sessions: make(map[*Session]struct{})}
	initial, _ := Prepare(contract.Config{DefaultAction: "deny", Scope: contract.Scope{AllInbounds: true}})
	c.active.Store(initial)
	c.evaluations.New = func() any { return netapi.NewPolicyContext() }
	return c
}

func validIdentity(subject netapi.TrafficSubject) bool {
	i := subject.Identity
	return i != nil && i.UserID != "" && i.CredentialID != "" && i.Valid()
}

func (c *Controller) Managed(subject netapi.TrafficSubject) bool {
	return c.active.Load().managed(subject)
}
func (c *Controller) Preflight(subject netapi.TrafficSubject) error {
	if !subject.External {
		return nil
	}
	if c.closed.Load() || subject.Identity != nil && !validIdentity(subject) || c.Managed(subject) && !validIdentity(subject) {
		c.denied.Add(1)
		return netapi.ErrTrafficAccessDenied
	}
	if c.active.Load().config.Enabled && subject.InboundID == "" {
		c.denied.Add(1)
		return netapi.ErrTrafficAccessDenied
	}
	return nil
}

func (c *Controller) decision(p *Prepared, subject netapi.TrafficSubject, original, resolved netapi.Address) contract.Decision {
	d := contract.Decision{Revision: p.config.Revision, Managed: p.managed(subject), Allowed: true, Reason: "unmanaged"}
	if !subject.External {
		return d
	}
	if c.closed.Load() {
		d.Allowed = false
		d.Reason = "closed"
		return d
	}
	if subject.Identity != nil && !validIdentity(subject) || d.Managed && !validIdentity(subject) {
		d.Allowed = false
		d.Reason = "identity_required"
		return d
	}
	if !d.Managed {
		return d
	}
	if subject.InboundID == "" {
		d.Allowed = false
		d.Reason = "inbound_required"
		return d
	}
	if resolved == nil || resolved.IsFqdn() {
		d.Allowed = false
		d.Reason = "unresolved_destination"
		return d
	}
	network := netapi.ParseAddressNetwork(resolved.Network())
	if network != netapi.TCP && network != netapi.UDP || original != nil && netapi.ParseAddressNetwork(original.Network()) != network {
		d.Allowed = false
		d.Reason = "invalid_transport"
		return d
	}
	endpoint := resolved.(netapi.IPAddress).AddrPort()
	if !endpoint.IsValid() || endpoint.Addr().Zone() != "" || endpoint.Port() == 0 {
		d.Allowed = false
		d.Reason = "unresolved_destination"
		return d
	}
	state := c.evaluations.Get().(*netapi.PolicyContext)
	state.SetSubject(subject)
	state.Original = original
	defer func() { state.SetSubject(netapi.TrafficSubject{}); state.Original = nil; c.evaluations.Put(state) }()
	for _, rule := range p.rules {
		if rule.match.Match(state, resolved) {
			d.RuleID = rule.id
			d.Allowed = rule.allow
			d.Reason = "rule"
			return d
		}
	}
	d.Allowed = p.config.DefaultAction == "allow"
	d.Reason = "default"
	return d
}

func (c *Controller) Preview(subject netapi.TrafficSubject, original, resolved netapi.Address) contract.Decision {
	return c.decision(c.active.Load(), subject, original, resolved)
}

func (c *Controller) Decide(subject netapi.TrafficSubject, original, resolved netapi.Address) contract.Decision {
	d := c.Preview(subject, original, resolved)
	if !d.Allowed {
		c.denied.Add(1)
	}
	return d
}
func (c *Controller) Check(subject netapi.TrafficSubject, original, resolved netapi.Address) error {
	if !c.Preview(subject, original, resolved).Allowed {
		c.denied.Add(1)
		return netapi.ErrTrafficAccessDenied
	}
	return nil
}
func (c *Controller) Config() contract.Config { return c.active.Load().Config() }

// Activate publishes first, then invalidates only sessions whose retained
// authorizations no longer allow access. Adapters check the current snapshot on
// later datagrams; TCP close callbacks finish before this method returns.
func (c *Controller) Activate(next *Prepared) {
	c.applyMu.Lock()
	defer c.applyMu.Unlock()
	c.mu.Lock()
	c.active.Store(next)
	sessions := make([]*Session, 0, len(c.sessions))
	for s := range c.sessions {
		sessions = append(sessions, s)
	}
	c.mu.Unlock()
	var revoked []*Session
	for _, s := range sessions {
		if s.revalidate(next) {
			c.revoked.Add(1)
			s.cancelTraffic(netapi.ErrTrafficAccessDenied)
			s.Close()
			if s.terminateTraffic != nil {
				revoked = append(revoked, s)
			}
		}
	}
	if len(revoked) == 0 {
		return
	}
	terminateRevokedSessions(revoked)
}

func terminateRevokedSessions(revoked []*Session) {
	// Every revoked transport has been interrupted before a graceful close
	// can block. Bound teardown concurrency instead of spawning per session.
	var index atomic.Int64
	var workers sync.WaitGroup
	for range min(16, len(revoked)) {
		workers.Go(func() {
			for {
				i := int(index.Add(1)) - 1
				if i >= len(revoked) {
					return
				}
				revoked[i].terminateTraffic()
			}
		})
	}
	workers.Wait()
}

func (c *Controller) NewSession(subject netapi.TrafficSubject, cancelTraffic func(error), terminate ...func()) (netapi.TrafficAccessSession, error) {
	if !subject.External {
		return nil, nil
	}
	if cancelTraffic == nil || len(terminate) > 1 {
		return nil, netapi.ErrTrafficAccessDenied
	}
	c.mu.Lock()
	if err := c.Preflight(subject); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	if len(c.sessions) >= maxSessions {
		c.mu.Unlock()
		c.capacityRejected.Add(1)
		return nil, netapi.ErrTrafficAccessDenied
	}
	s := &Session{owner: c, subject: subject, cancelTraffic: cancelTraffic}
	if len(terminate) == 1 {
		s.terminateTraffic = terminate[0]
	}
	c.sessions[s] = struct{}{}
	c.mu.Unlock()
	if subject.Identity != nil {
		stop := context.AfterFunc(subject.Identity.Context, s.invalidate)
		s.mu.Lock()
		if s.released {
			s.mu.Unlock()
			stop()
		} else {
			s.stop = stop
			s.mu.Unlock()
		}
	}
	return s, nil
}

func (c *Controller) Status() contract.Status {
	c.mu.Lock()
	n := len(c.sessions)
	c.mu.Unlock()
	return contract.Status{Revision: c.active.Load().config.Revision, Sessions: n, Denied: strconv.FormatUint(c.denied.Load(), 10), Revoked: strconv.FormatUint(c.revoked.Load(), 10), CapacityRejected: strconv.FormatUint(c.capacityRejected.Load(), 10)}
}

func (c *Controller) Close() error {
	c.applyMu.Lock()
	defer c.applyMu.Unlock()
	c.closed.Store(true)
	c.mu.Lock()
	sessions := make([]*Session, 0, len(c.sessions))
	for s := range c.sessions {
		sessions = append(sessions, s)
	}
	c.mu.Unlock()
	for _, s := range sessions {
		s.invalidate()
	}
	return nil
}

var _ netapi.TrafficAccess = (*Controller)(nil)
