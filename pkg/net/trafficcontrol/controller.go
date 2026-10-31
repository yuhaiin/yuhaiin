package trafficcontrol

import "sync"

// PolicyResolver is the only policy capability required by datagram adapters.
// Implementations resolve existing identities, never match packets again.
type PolicyResolver interface {
	Resolve(inboundID, routeID string) Policy
}

// BufferedResources charges memory and work at the protocol's ownership
// boundary. Protocol adapters decide when ownership starts/ends; all limits,
// hierarchy, denial accounting and admission algorithms live in this package.
type BufferedResources interface {
	ReserveQueueBytes(int64) bool
	ReleaseQueueBytes(int64)
	ReservePendingTask() bool
	ReleasePendingTask()
}
type Budget interface {
	BufferedResources
	AcquireSession() (*Session, bool)
	Snapshot() Counters
}

// UnlimitedBudget preserves the unmanaged adapter behavior without nil
// interface checks on packet accounting calls.
func UnlimitedBudget() Budget { return (*Governor)(nil) }

func NewDatagramBudget(parent *Governor) *Governor {
	return NewGovernor(Limits{MaxSessions: 16384, MaxQueueBytes: 64 << 20, MaxPendingTasks: 4096, SessionsPerSec: 1000, SessionBurst: 2048}, parent)
}

// Controller owns the engine's aggregate budgets and inbound scope lifetimes.
// Adapters hold leases, not the scope registry or default resource policy.
type Controller struct {
	closed bool
	*Manager
	root   *Governor
	nat    *Governor
	mu     sync.Mutex
	scopes map[string]*streamScope
}
type streamScope struct {
	governor *Governor
	retired  bool
}
type StreamLease struct {
	owner   *Controller
	id      string
	scope   *streamScope
	session *Session
	once    sync.Once
}

func NewController() *Controller {
	return newController(NewGovernor(Limits{MaxSessions: 65536, SessionsPerSec: 4000, SessionBurst: 8192}, nil))
}
func newController(root *Governor) *Controller {
	return &Controller{Manager: NewManager(), root: root, nat: NewDatagramBudget(root), scopes: make(map[string]*streamScope)}
}
func (c *Controller) DatagramBudget() Budget { return c.nat }

// AdmitDatagram shares the existing NAT/root budget while honoring controller
// shutdown. Probe adapters do not own a NAT table to enforce that lifetime.
func (c *Controller) AdmitDatagram() (*Session, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, false
	}
	return c.nat.AcquireSession()
}

func (c *Controller) AdmitStream(id string) (*StreamLease, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, false
	}
	scope := c.scopes[id]
	if scope == nil {
		scope = &streamScope{governor: NewGovernor(Limits{MaxSessions: 8192, SessionsPerSec: 1000, SessionBurst: 2048}, c.root)}
		c.scopes[id] = scope
	}
	lease, ok := scope.governor.AcquireSession()
	if !ok {
		return nil, false
	}
	return &StreamLease{owner: c, id: id, scope: scope, session: lease}, true
}

func (l *StreamLease) Release() {
	if l == nil {
		return
	}
	l.once.Do(func() {
		l.session.Release()
		c := l.owner
		c.mu.Lock()
		defer c.mu.Unlock()
		if l.scope.retired && l.scope.governor.Snapshot().Sessions == 0 && c.scopes[l.id] == l.scope {
			delete(c.scopes, l.id)
		}
	})
}

// ForgetInbound keeps an active retired scope until its last lease returns.
// A re-added identity therefore shares the original aggregate quota.
func (c *Controller) ForgetInbound(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if scope := c.scopes[id]; scope != nil {
		scope.retired = true
		if scope.governor.Snapshot().Sessions == 0 {
			delete(c.scopes, id)
		}
	}
}

func (c *Controller) Status() Status {
	st := Status{Global: c.root.Snapshot(), NAT: c.nat.Snapshot(), Shaping: c.Usage()}
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, scope := range c.scopes {
		if len(st.InboundScopes) == 64 {
			st.Truncated = true
			break
		}
		st.InboundScopes = append(st.InboundScopes, ScopeStatus{ID: id, Counters: scope.governor.Snapshot()})
	}
	return st
}
func (c *Controller) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	for id, scope := range c.scopes {
		scope.retired = true
		if scope.governor.Snapshot().Sessions == 0 {
			delete(c.scopes, id)
		}
	}
}
