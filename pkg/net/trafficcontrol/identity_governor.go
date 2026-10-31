package trafficcontrol

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/contract/resource"
)

// IdentityGovernor owns a user's (or credential's) budgets across listeners and
// devices. Protocol reservations precede total/CPS reservations, so repeatedly
// hitting a TCP cap cannot drain the UDP creation budget. There is no registry
// lookup or process-wide mutex in these operations.
type IdentityGovernor struct {
	mu              sync.Mutex
	total, tcp, udp *Governor
	limits          resource.Limits
	generation      atomic.Uint64
	lastRejected    atomic.Uint64
}

func (g *IdentityGovernor) reclaimable(now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.total.reclaimable(now)
}

type IdentityResources struct {
	LastRejection  string          `json:"lastRejection"`
	LastRejectedAt int64           `json:"lastRejectedAt"`
	Limits         resource.Limits `json:"limits"`
	Total          Counters        `json:"total"`
	TCP            Counters        `json:"tcp"`
	UDP            Counters        `json:"udp"`
}

func NewIdentityGovernor(limits resource.Limits) (*IdentityGovernor, error) {
	if err := resource.ValidateLimits(limits); err != nil {
		return nil, err
	}
	g := &IdentityGovernor{limits: limits}
	g.total = NewGovernor(identityTotalLimits(limits), nil)
	g.tcp = NewGovernor(Limits{MaxSessions: limits.MaxTCPSessions}, g.total)
	g.udp = NewGovernor(Limits{MaxSessions: limits.MaxUDPSessions}, g.total)
	return g, nil
}

func identityTotalLimits(l resource.Limits) Limits {
	return Limits{MaxSessions: l.MaxSessions, SessionsPerSec: l.ConnectionsPerSecond, SessionBurst: l.ConnectionBurst, PacketsPerSec: l.PacketsPerSecond, PacketBurst: l.PacketBurst}
}

func (g *IdentityGovernor) UpdateLimits(limits resource.Limits) error {
	if err := resource.ValidateLimits(limits); err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	// All values have already been validated. Child and parent limits are
	// published together with respect to new identity session admissions.
	_ = g.total.UpdateLimits(identityTotalLimits(limits))
	_ = g.tcp.UpdateLimits(Limits{MaxSessions: limits.MaxTCPSessions})
	_ = g.udp.UpdateLimits(Limits{MaxSessions: limits.MaxUDPSessions})
	g.limits = limits
	return nil
}

func (g *IdentityGovernor) AcquireTCP() (*Session, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.acquire(g.tcp, rejectTCPLimit)
}

// A UDP lease represents an association, never an individual destination.
func (g *IdentityGovernor) AcquireUDP() (*Session, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.acquire(g.udp, rejectUDPLimit)
}

func (g *IdentityGovernor) acquire(protocol *Governor, protocolReason rejection) (*Session, bool) {
	lease, reason, scope := protocol.acquireSession()
	if reason != rejectNone {
		if scope == protocol && reason == rejectSessionLimit {
			reason = protocolReason
		}
		g.recordRejection(reason, time.Now())
	}
	return lease, reason == rejectNone
}

func (g *IdentityGovernor) AdmitPacket(now time.Time) bool {
	if !g.total.AdmitPacket(now) {
		g.recordRejection(rejectPacketRate, now)
		return false
	}
	return true
}

func (g *IdentityGovernor) Snapshot() IdentityResources {
	g.mu.Lock()
	defer g.mu.Unlock()
	last := g.lastRejected.Load()
	return IdentityResources{Limits: g.limits, Total: g.total.Snapshot(), TCP: g.tcp.Snapshot(), UDP: g.udp.Snapshot(), LastRejection: rejectionNames[last&255], LastRejectedAt: int64(last >> 8)}
}
