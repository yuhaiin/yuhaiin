package dataplane

// Admission control for unauthenticated peers.
//
// Every handshake in this tree costs a responder something before it knows who
// it is talking to: a session identifier, an address from a pool, a
// Diffie-Hellman computation, a buffer held until a timeout. None of that is
// recoverable from the initiator, and none of it requires the initiator to prove
// anything first — that is inherent to how these protocols begin, not a flaw in
// any one of them.
//
// What was missing is a bound. Before this, a single host sending initiations at
// line rate would make every veepin server allocate until something ran out.
// Expiry timers, where protocols had them, bound how *long* state is held, not
// how much accumulates in that window.
//
// Two limits, because they fail differently:
//
//   - A global cap on concurrent half-open handshakes protects the server's
//     memory and address pool regardless of where the load comes from.
//   - A per-source rate limit stops one host consuming the whole cap, so a
//     single noisy or hostile peer cannot deny service to everyone else.
//
// Neither is a substitute for a protocol's own anti-DoS mechanism where one is
// specified — IKEv2's cookie exchange (RFC 7296 §2.6) and WireGuard's cookie
// reply (paper §5.4.7) both make the initiator prove return routability before
// the responder does any expensive work, which is strictly better because it
// costs the responder nothing. It also makes the per-source limit here
// meaningful, since the source has then been proved rather than claimed. This
// is the floor under every protocol, including those that have no such
// mechanism.

import (
	"net"
	"net/netip"
	"sync"
	"time"
)

// Defaults chosen to be generous. Admission control that rejects legitimate
// clients is worse than the attack it prevents, so these are set well above what
// a busy server sees and are expected to be tuned down only if a deployment has
// a reason.
const (
	// DefaultMaxHalfOpen is how many handshakes may be in flight at once.
	DefaultMaxHalfOpen = 512
	// DefaultPerSourceRate is how many handshakes one source address may start
	// per second, sustained.
	DefaultPerSourceRate = 10
	// DefaultPerSourceBurst is how far one source may exceed that momentarily.
	// A client retransmitting an unanswered handshake is normal and must not
	// be mistaken for an attack.
	DefaultPerSourceBurst = 20

	// sourceIdleTimeout is how long a source's rate-limit state is kept after
	// it goes quiet. Without eviction the limiter would itself become the
	// unbounded allocation it exists to prevent.
	sourceIdleTimeout = 5 * time.Minute
)

// AdmissionConfig configures a Gate. The zero value is usable and applies the
// defaults above.
type AdmissionConfig struct {
	MaxHalfOpen    int
	PerSourceRate  float64
	PerSourceBurst float64
	// Now is the clock, for tests. Nil means time.Now.
	Now func() time.Time
}

func (c AdmissionConfig) withDefaults() AdmissionConfig {
	if c.MaxHalfOpen <= 0 {
		c.MaxHalfOpen = DefaultMaxHalfOpen
	}
	if c.PerSourceRate <= 0 {
		c.PerSourceRate = DefaultPerSourceRate
	}
	if c.PerSourceBurst <= 0 {
		c.PerSourceBurst = DefaultPerSourceBurst
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return c
}

// RejectReason says why a handshake was refused, so a server can log something
// actionable instead of a bare drop.
type RejectReason int

const (
	// Admitted means the handshake may proceed.
	Admitted RejectReason = iota
	// RejectedAtCapacity means the global half-open limit is reached.
	RejectedAtCapacity
	// RejectedRateLimited means this source is starting handshakes too fast.
	RejectedRateLimited
)

func (r RejectReason) String() string {
	switch r {
	case Admitted:
		return "admitted"
	case RejectedAtCapacity:
		return "at half-open capacity"
	case RejectedRateLimited:
		return "source rate limited"
	default:
		return "unknown"
	}
}

// bucket is one source's token bucket.
type bucket struct {
	tokens float64
	last   time.Time
}

// Gate bounds how much unauthenticated work a server will accept. The zero value
// is not usable; call NewGate.
type Gate struct {
	cfg AdmissionConfig

	mu       sync.Mutex
	halfOpen int
	sources  map[netip.Addr]*bucket
	lastGC   time.Time
}

// NewGate builds a Gate.
func NewGate(cfg AdmissionConfig) *Gate {
	cfg = cfg.withDefaults()
	return &Gate{
		cfg:     cfg,
		sources: map[netip.Addr]*bucket{},
		lastGC:  cfg.Now(),
	}
}

// Admit decides whether to begin a handshake for a peer, and reserves capacity
// if so. A caller that is admitted must later call Done exactly once, whether
// the handshake completes, fails or times out — a leaked reservation is
// indistinguishable from an attack once the cap is reached.
//
// The rate limit is keyed on the source address rather than address and port,
// since a hostile source changes ports freely.
func (g *Gate) Admit(from net.Addr) RejectReason {
	addr := addrOf(from)

	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.cfg.Now()
	g.gc(now)

	// Rate first: a source over its limit should not consume a slot even when
	// the server is otherwise idle, or a single host could churn through the
	// whole cap by retrying.
	if !g.allowSource(addr, now) {
		return RejectedRateLimited
	}
	if g.halfOpen >= g.cfg.MaxHalfOpen {
		return RejectedAtCapacity
	}

	g.halfOpen++
	return Admitted
}

// Done releases a reservation taken by a successful Admit.
func (g *Gate) Done() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.halfOpen > 0 {
		g.halfOpen--
	}
}

// HalfOpen is how many handshakes are currently reserved, for logging and tests.
func (g *Gate) HalfOpen() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.halfOpen
}

// allowSource applies the per-source token bucket. Caller holds g.mu.
func (g *Gate) allowSource(addr netip.Addr, now time.Time) bool {
	b, ok := g.sources[addr]
	if !ok {
		b = &bucket{tokens: g.cfg.PerSourceBurst, last: now}
		g.sources[addr] = b
	}

	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens = min(b.tokens+elapsed*g.cfg.PerSourceRate, g.cfg.PerSourceBurst)
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// gc evicts idle sources so the limiter's own state stays bounded. Caller holds
// g.mu.
func (g *Gate) gc(now time.Time) {
	if now.Sub(g.lastGC) < sourceIdleTimeout {
		return
	}
	g.lastGC = now
	for addr, b := range g.sources {
		if now.Sub(b.last) > sourceIdleTimeout {
			delete(g.sources, addr)
		}
	}
}

// addrOf extracts the address from the shapes a server's read loop produces.
func addrOf(a net.Addr) netip.Addr {
	switch v := a.(type) {
	case *net.UDPAddr:
		if ip, ok := netip.AddrFromSlice(v.IP); ok {
			return ip.Unmap()
		}
	case *net.TCPAddr:
		if ip, ok := netip.AddrFromSlice(v.IP); ok {
			return ip.Unmap()
		}
	case interface{ AddrPort() netip.AddrPort }:
		return v.AddrPort().Addr().Unmap()
	}
	// An address shape we do not recognise is rate-limited as one bucket rather
	// than exempted: failing closed is the safer default here, and nothing in
	// this tree produces one.
	return netip.Addr{}
}
