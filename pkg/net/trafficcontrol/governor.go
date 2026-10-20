// Package trafficcontrol provides bounded resource admission and fair queues.
// It is independent of protocol stacks, transport implementations and the UI.
package trafficcontrol

import (
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
	limits                   Limits
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

func NewGovernor(l Limits, parent *Governor) *Governor {
	if l.MaxSessions < 0 || l.MaxQueueBytes < 0 || l.MaxPendingTasks < 0 || l.SessionsPerSec < 0 || l.SessionBurst < 0 || l.PacketsPerSec < 0 || l.PacketBurst < 0 {
		panic("trafficcontrol: negative resource limit")
	}
	if l.SessionsPerSec > 0 && l.SessionBurst == 0 {
		l.SessionBurst = l.SessionsPerSec
	}
	if l.PacketsPerSec > 0 && l.PacketBurst == 0 {
		l.PacketBurst = l.PacketsPerSec
	}
	return &Governor{parent: parent, limits: l, tokens: l.PacketBurst, sessionTokens: l.SessionBurst}
}

// Session is a single owned reservation; Release may be called concurrently
// or repeatedly, including on failure and shutdown paths.
type Session struct {
	owner  *Governor
	parent *Session
	once   sync.Once
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
	if g == nil {
		return nil, true
	}
	// Always evaluate the local concurrency and CPS budget before touching
	// the parent governor. Otherwise an abusive over-quota child could drain
	// the parent's token bucket and deny unrelated healthy peers.
	if !reserve(&g.sessions, 1, g.limits.MaxSessions) {
		g.deniedSessions.Add(1)
		return nil, false
	}
	if !g.admitSession(time.Now()) {
		g.sessions.Add(-1)
		g.deniedSessions.Add(1)
		g.deniedRateSessions.Add(1)
		return nil, false
	}
	var parent *Session
	if g.parent != nil {
		var ok bool
		parent, ok = g.parent.AcquireSession()
		if !ok {
			g.sessions.Add(-1)
			g.deniedSessions.Add(1)
			return nil, false
		}
	}
	return &Session{owner: g, parent: parent}, true
}

// admitSession uses a separate token bucket, so an existing active session
// never loses progress merely because another peer floods new handshakes.
func (g *Governor) admitSession(now time.Time) bool {
	if g.limits.SessionsPerSec == 0 {
		return true
	}
	g.mu.Lock()
	if g.sessionLast.IsZero() {
		g.sessionLast = now
	} else if elapsed := now.Sub(g.sessionLast).Seconds(); elapsed > 0 {
		g.sessionTokens = min(g.limits.SessionBurst, g.sessionTokens+elapsed*g.limits.SessionsPerSec)
		g.sessionLast = now
	}
	ok := g.sessionTokens >= 1
	if ok {
		g.sessionTokens--
	}
	g.mu.Unlock()
	return ok
}

func (l *Session) Release() {
	if l == nil {
		return
	}
	l.once.Do(func() {
		l.owner.sessions.Add(-1)
		l.parent.Release()
	})
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
	if !reserve(&g.bytes, n, g.limits.MaxQueueBytes) {
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
	if !reserve(&g.pending, 1, g.limits.MaxPendingTasks) {
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
	if g.limits.PacketsPerSec == 0 {
		if g.parent != nil {
			if !g.parent.AdmitPacket(now) {
				g.deniedPackets.Add(1)
				return false
			}
		}
		return true
	}
	g.mu.Lock()
	if g.last.IsZero() {
		g.last = now
	} else if elapsed := now.Sub(g.last).Seconds(); elapsed > 0 {
		g.tokens = min(g.limits.PacketBurst, g.tokens+elapsed*g.limits.PacketsPerSec)
		g.last = now
	}
	ok := g.tokens >= 1
	if ok {
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
