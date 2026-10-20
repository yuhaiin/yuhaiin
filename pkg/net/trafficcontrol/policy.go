package trafficcontrol

import (
	"errors"
	"fmt"
	"maps"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Rate struct {
	BytesPerSecond int64 `json:"bytesPerSecond"`
	BurstBytes     int64 `json:"burstBytes"`
}

type Profile struct {
	Upload   Rate `json:"upload"`
	Download Rate `json:"download"`
}

// Config is a policy snapshot; rule IDs are taken from the existing router,
// not matched by a separate QoS rule engine. A bound profile is a shared
// group limit per inbound/rule identity, not a per-TCP-connection limit.
type Config struct {
	Enabled         bool               `json:"enabled"`
	Global          Profile            `json:"global"`
	DefaultProfile  string             `json:"defaultProfile,omitempty"`
	Profiles        map[string]Profile `json:"profiles,omitempty"`
	InboundProfiles map[string]string  `json:"inboundProfiles,omitempty"`
	RouteProfiles   map[string]string  `json:"routeProfiles,omitempty"`
}

type compiledPair struct {
	up, down *Limiter
	spec     Profile
}

func compilePair(spec Profile) (compiledPair, error) {
	up, err := NewLimiter(spec.Upload.BytesPerSecond, spec.Upload.BurstBytes)
	if err != nil {
		return compiledPair{}, fmt.Errorf("upload: %w", err)
	}
	down, err := NewLimiter(spec.Download.BytesPerSecond, spec.Download.BurstBytes)
	if err != nil {
		return compiledPair{}, fmt.Errorf("download: %w", err)
	}
	return compiledPair{up: up, down: down, spec: spec}, nil
}

type policySnapshot struct {
	changed          chan struct{}
	config           Config
	global, fallback compiledPair
	inbound, route   map[string]compiledPair
}

type shapingUsage struct{ acceptedUp, acceptedDown, rejectedUp, rejectedDown, waitNanos atomic.Uint64 }

type Usage struct {
	AdmittedUploadBytes       uint64 `json:"admittedUploadBytes"`
	AdmittedDownloadBytes     uint64 `json:"admittedDownloadBytes"`
	RejectedUploadDatagrams   uint64 `json:"rejectedUploadDatagrams"`
	RejectedDownloadDatagrams uint64 `json:"rejectedDownloadDatagrams"`
	PacingWaitNanos           uint64 `json:"pacingWaitNanos"`
}

// Manager publishes immutable policy selection while retaining aggregate budgets
// across configuration changes. All managed admissions lock their direction's
// global bucket first, so activation can update every scope as one transaction.
type Manager struct {
	mu     sync.Mutex
	usage  shapingUsage
	global compiledPair
	active atomic.Pointer[policySnapshot]
}

func NewManager() *Manager {
	m := &Manager{global: compiledPair{up: new(Limiter), down: new(Limiter)}}
	m.active.Store(&policySnapshot{global: m.global, changed: make(chan struct{})})
	return m
}

func cloneConfig(c Config) Config {
	c.Profiles = maps.Clone(c.Profiles)
	c.InboundProfiles = maps.Clone(c.InboundProfiles)
	c.RouteProfiles = maps.Clone(c.RouteProfiles)
	return c
}

func (m *Manager) Config() Config {
	if m == nil {
		return Config{}
	}
	s := m.active.Load()
	if s == nil {
		return Config{}
	}
	return cloneConfig(s.config)
}

func compilePolicy(c Config) (*policySnapshot, error) {
	c = cloneConfig(c)
	s := &policySnapshot{config: c, changed: make(chan struct{}), inbound: make(map[string]compiledPair), route: make(map[string]compiledPair)}
	var err error
	s.global, err = compilePair(c.Global)
	if err != nil {
		return nil, fmt.Errorf("global: %w", err)
	}
	for id, p := range c.Profiles {
		if strings.TrimSpace(id) == "" {
			return nil, errors.New("trafficcontrol: empty profile ID")
		}
		if _, err = compilePair(p); err != nil {
			return nil, fmt.Errorf("profile %q: %w", id, err)
		}
	}
	profile := func(id string) (Profile, error) {
		p, ok := c.Profiles[id]
		if !ok {
			return Profile{}, fmt.Errorf("trafficcontrol: unknown profile %q", id)
		}
		return p, nil
	}
	if c.DefaultProfile != "" {
		p, e := profile(c.DefaultProfile)
		if e != nil {
			return nil, e
		}
		s.fallback, err = compilePair(p)
		if err != nil {
			return nil, err
		}
	}
	for id, name := range c.InboundProfiles {
		if strings.TrimSpace(id) == "" {
			return nil, errors.New("trafficcontrol: empty inbound ID")
		}
		p, e := profile(name)
		if e != nil {
			return nil, fmt.Errorf("inbound %q: %w", id, e)
		}
		s.inbound[id], err = compilePair(p)
		if err != nil {
			return nil, err
		}
	}
	for id, name := range c.RouteProfiles {
		if strings.TrimSpace(id) == "" {
			return nil, errors.New("trafficcontrol: empty route rule ID")
		}
		p, e := profile(name)
		if e != nil {
			return nil, fmt.Errorf("rule %q: %w", id, e)
		}
		s.route[id], err = compilePair(p)
		if err != nil {
			return nil, err
		}
	}
	return s, nil
}

// ValidateConfig compiles references and rates without creating live budgets.
func ValidateConfig(c Config) error { _, err := compilePolicy(c); return err }

// Apply validates completely before touching live budgets. Unchanged scopes
// preserve credits; changed rates retain the existing byte balance, clamped to
// the new burst. Removed bindings disappear from subsequent stream operations.
func (m *Manager) Apply(c Config) error {
	if m == nil {
		return errors.New("trafficcontrol: nil manager")
	}
	next, err := compilePolicy(c)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.global.up == nil {
		m.global = compiledPair{up: new(Limiter), down: new(Limiter)}
	}
	m.global.up.mu.Lock()
	m.global.down.mu.Lock()
	defer m.global.up.mu.Unlock()
	defer m.global.down.mu.Unlock()
	old := m.active.Load()
	now := time.Now()
	next.global = retainPair(m.global, next.global, now)
	if old != nil {
		next.fallback = retainPair(old.fallback, next.fallback, now)
		for id, pair := range next.inbound {
			next.inbound[id] = retainPair(old.inbound[id], pair, now)
		}
		for id, pair := range next.route {
			next.route[id] = retainPair(old.route[id], pair, now)
		}
	}
	m.active.Store(next)
	if old != nil {
		close(old.changed)
	}
	return nil
}

// Caller holds both global admission locks; no managed child admission can be
// running. Only the policy snapshot's immutable spec is read without a lock.
func retainPair(old, next compiledPair, now time.Time) compiledPair {
	next.up = retainLimiter(old.up, next.up, now)
	next.down = retainLimiter(old.down, next.down, now)
	return next
}

func retainLimiter(old, next *Limiter, now time.Time) *Limiter {
	if old == nil {
		return next
	}
	rate, burst := int64(0), int64(0)
	if next != nil {
		rate, burst = next.rate, next.burst
	}
	if old.rate == rate && old.burst == burst {
		return old
	}
	balance := float64(burst)
	if old.rate > 0 {
		balance = min(float64(old.burst), float64(now.Sub(old.next))*float64(old.rate)/float64(time.Second))
	}
	old.rate, old.burst = rate, burst
	if rate == 0 {
		old.next = time.Time{}
	} else {
		balance = min(float64(burst), balance)
		old.next = now.Add(-time.Duration(balance * float64(time.Second) / float64(rate)))
	}
	return old
}

func (m *Manager) Usage() Usage {
	if m == nil {
		return Usage{}
	}
	return Usage{AdmittedUploadBytes: m.usage.acceptedUp.Load(), AdmittedDownloadBytes: m.usage.acceptedDown.Load(),
		RejectedUploadDatagrams: m.usage.rejectedUp.Load(), RejectedDownloadDatagrams: m.usage.rejectedDown.Load(),
		PacingWaitNanos: m.usage.waitNanos.Load()}
}

// Resolve binds only routing identities. Each stream operation observes the
// current selection, so established streams share new global caps immediately.
func (m *Manager) Resolve(inboundID, routeID string) Policy {
	if m == nil {
		return Policy{}
	}
	s := m.active.Load()
	if s == nil {
		return Policy{}
	}
	up, down, _, _ := s.scopes(inboundID, routeID)
	return Policy{manager: m, inboundID: inboundID, routeID: routeID, up: up, down: down, usage: &m.usage}
}

func (s *policySnapshot) scopes(inboundID, routeID string) (up, down [3]*Limiter, upEnabled, downEnabled bool) {
	if !s.config.Enabled {
		return
	}
	inbound, hasInbound := s.inbound[inboundID]
	rule, hasRule := s.route[routeID]
	fallback := s.fallback
	if hasInbound || hasRule {
		fallback = inbound
	}
	pairs := [3]compiledPair{s.global, fallback, rule}
	for i, pair := range pairs {
		up[i], down[i] = pair.up, pair.down
		upEnabled = upEnabled || pair.spec.Upload.BytesPerSecond > 0
		downEnabled = downEnabled || pair.spec.Download.BytesPerSecond > 0
	}
	return
}
