// Package trafficcontrol provides bounded resource admission and fair queues.
// It is independent of protocol stacks, transport implementations and the UI.
package trafficcontrol

import (
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// Limits specify hard reservations charged to a Governor. A zero limit means
// unlimited. Rate limits apply to new packet admissions, not existing queues.
type Limits struct {
	MaxSessions     int64
	MaxQueueBytes   int64
	MaxPendingTasks int64
	// SessionsPerSec is a creation-rate budget (CPS), separate from the
	// number of live sessions. It is evaluated only on new admissions.
	SessionsPerSec float64
	SessionBurst   float64
	PacketsPerSec  float64
	PacketBurst    float64
}

type Counters struct {
	Sessions, QueueBytes, PendingTasks         int64
	DeniedSessions, DeniedBytes, DeniedPending uint64
	DeniedRateSessions                         uint64
	DeniedPackets                              uint64
}

type Governor struct {
	parent                   *Governor
	limits                   atomic.Pointer[Limits]
	sessions, bytes, pending atomic.Int64
	deniedSessions           atomic.Uint64
	deniedRateSessions       atomic.Uint64
	deniedBytes              atomic.Uint64
	deniedPending            atomic.Uint64
	deniedPackets            atomic.Uint64
	mu                       sync.Mutex
	tokens                   float64
	last                     time.Time
	sessionTokens            float64
	sessionLast              time.Time
}

func normalizeLimits(l Limits) (Limits, error) {
	if l.MaxSessions < 0 || l.MaxQueueBytes < 0 || l.MaxPendingTasks < 0 {
		return l, errors.New("trafficcontrol: negative resource limit")
	}
	for _, n := range []float64{l.SessionsPerSec, l.SessionBurst, l.PacketsPerSec, l.PacketBurst} {
		if n < 0 || math.IsNaN(n) || math.IsInf(n, 0) {
			return l, errors.New("trafficcontrol: invalid resource rate")
		}
	}
	if l.SessionsPerSec > 0 && l.SessionBurst == 0 {
		l.SessionBurst = max(1, l.SessionsPerSec)
	}
	if l.PacketsPerSec > 0 && l.PacketBurst == 0 {
		l.PacketBurst = max(1, l.PacketsPerSec)
	}
	return l, nil
}

func NewGovernor(l Limits, parent *Governor) *Governor {
	l, err := normalizeLimits(l)
	if err != nil {
		panic(err)
	}
	g := &Governor{parent: parent, tokens: l.PacketBurst, sessionTokens: l.SessionBurst}
	g.limits.Store(new(l))
	return g
}

// UpdateLimits preserves live reservations and earned rate credits. Lowering a
// concurrency limit blocks new admissions until old leases drain; it never
// resets counters or creates fresh bursts for reconnecting clients.
func (g *Governor) UpdateLimits(l Limits) error {
	l, err := normalizeLimits(l)
	if err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	old := g.limits.Load()
	now := time.Now()
	refill(&g.sessionTokens, &g.sessionLast, old.SessionsPerSec, old.SessionBurst, now)
	refill(&g.tokens, &g.last, old.PacketsPerSec, old.PacketBurst, now)
	g.sessionTokens = min(g.sessionTokens, l.SessionBurst)
	g.tokens = min(g.tokens, l.PacketBurst)
	if old.SessionsPerSec == 0 && l.SessionsPerSec > 0 {
		g.sessionTokens = l.SessionBurst
	}
	if old.PacketsPerSec == 0 && l.PacketsPerSec > 0 {
		g.tokens = l.PacketBurst
	}
	g.limits.Store(new(l))
	return nil
}

func refill(tokens *float64, last *time.Time, rate, burst float64, now time.Time) {
	if !last.IsZero() && now.After(*last) {
		*tokens = min(burst, *tokens+now.Sub(*last).Seconds()*rate)
	}
	*last = now
}

// Session is a single owned reservation; Release may be called concurrently
// or repeatedly, including on failure and shutdown paths.
type Session struct {
	owner     *Governor
	parent    *Session
	once      sync.Once
	resources *ResourceSession
}

func reserve(counter *atomic.Int64, n, limit int64) bool {
	if n < 0 {
		return false
	}
	for {
		previous := counter.Load()
		if n > int64(^uint64(0)>>1)-previous || limit > 0 && n > limit-previous {
			return false
		}
		if counter.CompareAndSwap(previous, previous+n) {
			return true
		}
	}
}

func (g *Governor) AcquireSession() (*Session, bool) {
	session, reason, _ := g.acquireSession()
	return session, reason == rejectNone
}

func (g *Governor) acquireSession() (*Session, rejection, *Governor) {
	if g == nil {
		return nil, rejectNone, nil
	}
	// Always evaluate the local concurrency and CPS budget before touching
	// the parent governor. Otherwise an abusive over-quota child could drain
	// the parent's token bucket and deny unrelated healthy peers.
	g.mu.Lock()
	limits := g.limits.Load()
	if !reserve(&g.sessions, 1, limits.MaxSessions) {
		g.mu.Unlock()
		g.deniedSessions.Add(1)
		return nil, rejectSessionLimit, g
	}
	if !g.admitSession(limits, time.Now()) {
		g.sessions.Add(-1)
		g.mu.Unlock()
		g.deniedSessions.Add(1)
		g.deniedRateSessions.Add(1)
		return nil, rejectConnectionRate, g
	}
	g.mu.Unlock()
	var parent *Session
	if g.parent != nil {
		var reason rejection
		var scope *Governor
		parent, reason, scope = g.parent.acquireSession()
		if reason != rejectNone {
			g.sessions.Add(-1)
			g.deniedSessions.Add(1)
			return nil, reason, scope
		}
	}
	return &Session{owner: g, parent: parent}, rejectNone, nil
}

// admitSession uses a separate token bucket, so an existing active session
// never loses progress merely because another peer floods new handshakes.
func (g *Governor) admitSession(limits *Limits, now time.Time) bool {
	if limits.SessionsPerSec == 0 {
		return true
	}
	refill(&g.sessionTokens, &g.sessionLast, limits.SessionsPerSec, limits.SessionBurst, now)
	ok := g.sessionTokens >= 1
	if ok {
		g.sessionTokens--
	}
	return ok
}

func (l *Session) Release() {
	if l == nil {
		return
	}
	l.once.Do(func() {
		if l.owner != nil {
			l.owner.sessions.Add(-1)
		}
		l.parent.Release()
		l.resources.Release()
	})
}

// BindSessionResources transfers an identity lease to the existing transport
// lease before it becomes visible to workers. Normal/failure/shutdown cleanup
// then releases both through the same idempotent ownership boundary.
func BindSessionResources(session *Session, resources *ResourceSession) *Session {
	if resources == nil {
		return session
	}
	if session == nil {
		return &Session{resources: resources}
	}
	session.resources = resources
	return session
}

func (g *Governor) reclaimable(now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	l := g.limits.Load()
	refill(&g.sessionTokens, &g.sessionLast, l.SessionsPerSec, l.SessionBurst, now)
	refill(&g.tokens, &g.last, l.PacketsPerSec, l.PacketBurst, now)
	return g.sessions.Load() == 0 && g.bytes.Load() == 0 && g.pending.Load() == 0 && (l.SessionsPerSec == 0 || g.sessionTokens >= l.SessionBurst) && (l.PacketsPerSec == 0 || g.tokens >= l.PacketBurst)
}

// ReserveQueueBytes charges the entire hierarchy, rolling back if any scope
// rejects. Call ReleaseQueueBytes once on every successful reservation.
func (g *Governor) ReserveQueueBytes(n int64) bool {
	if g == nil {
		return true
	}
	if n < 0 {
		return false
	}
	if g.parent != nil && !g.parent.ReserveQueueBytes(n) {
		g.deniedBytes.Add(1)
		return false
	}
	if !reserve(&g.bytes, n, g.limits.Load().MaxQueueBytes) {
		if g.parent != nil {
			g.parent.ReleaseQueueBytes(n)
		}
		g.deniedBytes.Add(1)
		return false
	}
	return true
}

func (g *Governor) ReleaseQueueBytes(n int64) {
	if g == nil || n == 0 {
		return
	}
	if n < 0 {
		panic("trafficcontrol: negative release")
	}
	if remaining := g.bytes.Add(-n); remaining < 0 {
		panic("trafficcontrol: queue bytes released more than reserved")
	}
	g.parent.ReleaseQueueBytes(n)
}

// ReservePendingTask bounds asynchronous work separately from session and
// byte limits. Reserve before starting a task and release after it terminates.
func (g *Governor) ReservePendingTask() bool {
	if g == nil {
		return true
	}
	if g.parent != nil && !g.parent.ReservePendingTask() {
		g.deniedPending.Add(1)
		return false
	}
	if !reserve(&g.pending, 1, g.limits.Load().MaxPendingTasks) {
		if g.parent != nil {
			g.parent.ReleasePendingTask()
		}
		g.deniedPending.Add(1)
		return false
	}
	return true
}
func (g *Governor) ReleasePendingTask() {
	if g == nil {
		return
	}
	if remain := g.pending.Add(-1); remain < 0 {
		panic("trafficcontrol: pending task released more than reserved")
	}
	g.parent.ReleasePendingTask()
}

// AdmitPacket implements a bounded token bucket using the caller's timestamp;
// callers can skip it if the configured rate is zero. It intentionally does not
// allocate, create timers or hold a lock during packet processing.
func (g *Governor) AdmitPacket(now time.Time) bool {
	if g == nil {
		return true
	}
	if g.limits.Load().PacketsPerSec == 0 {
		if g.parent != nil {
			if !g.parent.AdmitPacket(now) {
				g.deniedPackets.Add(1)
				return false
			}
		}
		return true
	}
	g.mu.Lock()
	limits := g.limits.Load()
	refill(&g.tokens, &g.last, limits.PacketsPerSec, limits.PacketBurst, now)
	ok := limits.PacketsPerSec == 0 || g.tokens >= 1
	if ok && limits.PacketsPerSec != 0 {
		g.tokens--
	}
	g.mu.Unlock()
	if !ok {
		g.deniedPackets.Add(1)
		return false
	}
	if g.parent != nil && !g.parent.AdmitPacket(now) {
		g.deniedPackets.Add(1)
		return false
	}
	return true
}

func (g *Governor) Snapshot() Counters {
	if g == nil {
		return Counters{}
	}
	return Counters{
		Sessions: g.sessions.Load(), QueueBytes: g.bytes.Load(), PendingTasks: g.pending.Load(),
		DeniedSessions: g.deniedSessions.Load(), DeniedBytes: g.deniedBytes.Load(),
		DeniedRateSessions: g.deniedRateSessions.Load(), DeniedPending: g.deniedPending.Load(),
		DeniedPackets: g.deniedPackets.Load(),
	}
}
