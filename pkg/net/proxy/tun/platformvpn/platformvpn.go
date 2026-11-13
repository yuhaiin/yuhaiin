// Package platformvpn runs a lightweight TUN inbound on a device that the host
// platform creates on demand, such as an Android VpnService interface.
//
// The Go core owns the policy (addresses, routes, FakeIP pools, MTU) and the
// packet stack. The platform owns the OS VPN session and its descriptor:
//
//   - Provider.Establish returns a descriptor BORROWED from the platform. It
//     stays valid until Provider.Release is called with the same generation.
//     The TUN device duplicates it, so Go never closes the platform's fd and
//     the platform never closes Go's duplicate.
//   - Every Establish call gets a new, process-unique generation. Release and
//     platform callbacks (for example revoke) name a generation, so a stale
//     callback can never stop a newer interface.
//   - Start, reconfigure and close of one accepter are serialized. FakeIP
//     updates are coalesced and applied only when the requested configuration
//     differs from the applied one.
package platformvpn

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/device"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweight"
	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol"
)

// Scheme marks a TUN inbound whose device is supplied by the platform.
const Scheme = "platform"

// DeviceName is the canonical TUN name of the Android VPN inbound.
const DeviceName = Scheme + "://vpn"

// IsDevice reports whether a TUN name refers to a platform-provided device.
func IsDevice(name string) bool { return strings.HasPrefix(name, Scheme+"://") }

// Config is the platform VPN configuration requested by the core. It contains
// only values the core owns. Platform-side preferences (per-app rules, the
// Android route profile, metered mode) are applied by the provider and
// represented here only by Revision, which changes when they change.
type Config struct {
	MTU          int32    `json:"mtu"`
	IPv4         string   `json:"ipv4,omitempty"`
	IPv4Prefix   int      `json:"ipv4Prefix,omitempty"`
	IPv6         string   `json:"ipv6,omitempty"`
	IPv6Prefix   int      `json:"ipv6Prefix,omitempty"`
	DNS          []string `json:"dns"`
	Routes       []string `json:"routes"`
	Excludes     []string `json:"excludes"`
	FakeIPRoutes []string `json:"fakeIpRoutes"`
	// RouteMode is set when Routes come from System Network route rules. The
	// platform then installs exactly Routes (plus the TUN subnets and FakeIP
	// routes) and ignores its own route profile, so desktop and Android
	// capture the same destinations.
	RouteMode string `json:"routeMode,omitempty"`
	Revision  uint64 `json:"platformRevision"`
}

func (c Config) Equal(o Config) bool {
	return c.MTU == o.MTU && c.IPv4 == o.IPv4 && c.IPv4Prefix == o.IPv4Prefix &&
		c.IPv6 == o.IPv6 && c.IPv6Prefix == o.IPv6Prefix && c.Revision == o.Revision && c.RouteMode == o.RouteMode &&
		slices.Equal(c.DNS, o.DNS) && slices.Equal(c.Routes, o.Routes) &&
		slices.Equal(c.Excludes, o.Excludes) && slices.Equal(c.FakeIPRoutes, o.FakeIPRoutes)
}

func (c Config) clone() *Config {
	c.DNS = slices.Clone(c.DNS)
	c.Routes = slices.Clone(c.Routes)
	c.Excludes = slices.Clone(c.Excludes)
	c.FakeIPRoutes = slices.Clone(c.FakeIPRoutes)
	return &c
}

// Provider creates and destroys platform VPN interfaces.
type Provider interface {
	// Establish creates (or replaces) the platform interface for generation.
	// The returned descriptor is borrowed until Release(generation).
	Establish(ctx context.Context, generation uint64, config Config) (fd int, err error)
	// Release closes the platform resources of generation. It must be
	// idempotent and must ignore unknown generations.
	Release(generation uint64)
}

// Error codes reported to the management API.
const (
	CodePermissionRequired  = "permission_required"
	CodeConsentRequired     = "consent_required"
	CodeProviderUnavailable = "provider_unavailable"
	CodeEstablishFailed     = "establish_failed"
	CodeStackFailed         = "stack_failed"
	CodeBusy                = "busy"
	CodeRevoked             = "revoked"
)

// Error carries a stable code for the UI next to a human readable message.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// ErrorCode extracts a stable code. Providers implemented in other languages
// report errors as "<code>: <message>" strings.
func ErrorCode(err error) string {
	if err == nil {
		return ""
	}
	if e, ok := errors.AsType[*Error](err); ok {
		return e.Code
	}
	msg := err.Error()
	for _, code := range []string{CodePermissionRequired, CodeConsentRequired, CodeProviderUnavailable, CodeBusy} {
		if strings.Contains(msg, code) {
			return code
		}
	}
	return CodeEstablishFailed
}

type State string

const (
	StateStopped       State = "stopped"
	StateEstablishing  State = "establishing"
	StateRunning       State = "running"
	StateReconfiguring State = "reconfiguring"
	StateStopping      State = "stopping"
	StateFailed        State = "failed"
	StateRevoked       State = "revoked"
)

// Status is the runtime state of the platform VPN. Applied is what the
// platform interface currently uses; Pending is a requested configuration that
// is being applied.
type Status struct {
	State               State   `json:"state"`
	InboundID           string  `json:"inboundId,omitempty"`
	Generation          uint64  `json:"generation"`
	Applied             *Config `json:"applied,omitempty"`
	Pending             *Config `json:"pending,omitempty"`
	LastError           string  `json:"lastError,omitempty"`
	ErrorCode           string  `json:"errorCode,omitempty"`
	Reconfigurations    uint64  `json:"reconfigurations"`
	ReconfigureFailures uint64  `json:"reconfigureFailures"`
	LastReconfigureAt   int64   `json:"lastReconfigureAt,omitempty"`
	LastSwitchMillis    int64   `json:"lastSwitchMillis,omitempty"`
	StartedAt           int64   `json:"startedAt,omitempty"`
	ChangedAt           int64   `json:"changedAt"`
}

// Opener builds the packet stack for a borrowed descriptor configuration.
type Opener func(device.TunConfig) (netapi.Accepter, error)

// Spec is the core configuration of one platform TUN inbound.
type Spec struct {
	// Stack is the template for the lightweight stack; Name, routes and
	// automatic route management are replaced by the accepter.
	Stack           device.TunConfig
	Routes          []string
	Excludes        []string
	AutoFakeIPRoute bool
	// RouteMode marks Routes as generated by System Network rules; see
	// Config.RouteMode. Without it the platform applies its route profile.
	RouteMode string
}

// RouteModeSystemNetwork marks routes owned by the System Network Manager.
const RouteModeSystemNetwork = "system_network"

// SetRoutes replaces the routes from System Network rules and applies them if
// they changed. managed false returns the routes to the platform profile.
func (a *Accepter) SetRoutes(routes []string, managed bool) error {
	a.mu.Lock()
	a.spec.Routes, a.spec.Excludes, a.spec.RouteMode = slices.Clone(routes), nil, ""
	if managed {
		a.spec.RouteMode = RouteModeSystemNetwork
	}
	a.mu.Unlock()
	return a.Apply()
}

// Manager tracks the provider and the single active platform VPN. Android
// allows one VPN per app, so a second platform TUN inbound is rejected.
type Manager struct {
	mu        sync.Mutex
	provider  Provider
	active    *Accepter
	status    Status
	listeners map[uint64]func(Status)
	nextID    uint64
	revision  uint64

	generation atomic.Uint64

	// Addresses chooses interface prefixes when the inbound leaves them empty.
	Addresses func() (v4, v6 netip.Prefix, err error)
	// DefaultMTU is used when the inbound MTU is zero.
	DefaultMTU func() int32
	// Debounce coalesces FakeIP update bursts.
	Debounce time.Duration
	// EstablishTimeout bounds one Provider.Establish call.
	EstablishTimeout time.Duration
}

// Default is the process-wide manager used by the inbound runtime.
var Default = NewManager()

func NewManager() *Manager {
	return &Manager{
		status:           Status{State: StateStopped, ChangedAt: time.Now().UnixMilli()},
		Debounce:         300 * time.Millisecond,
		EstablishTimeout: 20 * time.Second,
	}
}

func (m *Manager) SetProvider(p Provider) {
	m.mu.Lock()
	m.provider = p
	m.mu.Unlock()
}

func (m *Manager) Provider() Provider {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.provider
}

func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.snapshotLocked()
}

func (m *Manager) snapshotLocked() Status {
	s := m.status
	if s.Applied != nil {
		s.Applied = s.Applied.clone()
	}
	if s.Pending != nil {
		s.Pending = s.Pending.clone()
	}
	return s
}

// Subscribe registers fn for status changes. fn runs synchronously and must
// not block or call back into the accepter.
func (m *Manager) Subscribe(fn func(Status)) func() {
	m.mu.Lock()
	if m.listeners == nil {
		m.listeners = map[uint64]func(Status){}
	}
	m.nextID++
	id := m.nextID
	m.listeners[id] = fn
	m.mu.Unlock()
	return sync.OnceFunc(func() {
		m.mu.Lock()
		delete(m.listeners, id)
		m.mu.Unlock()
	})
}

func (m *Manager) update(fn func(*Status)) {
	m.mu.Lock()
	fn(&m.status)
	m.status.ChangedAt = time.Now().UnixMilli()
	snapshot := m.snapshotLocked()
	listeners := make([]func(Status), 0, len(m.listeners))
	for _, l := range m.listeners {
		listeners = append(listeners, l)
	}
	m.mu.Unlock()
	for _, l := range listeners {
		l(snapshot)
	}
}

// RequestReconfigure records a platform-side preference change (per-app VPN,
// route profile, ...) and rebuilds the active interface. It is a no-op while
// no platform VPN is active.
func (m *Manager) RequestReconfigure() {
	m.mu.Lock()
	m.revision++
	active := m.active
	m.mu.Unlock()
	if active != nil {
		active.kick()
	}
}

func (m *Manager) currentRevision() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.revision
}

// Revoked handles a platform revoke of generation. Callbacks for older
// generations are ignored. It reports whether the active VPN was stopped.
func (m *Manager) Revoked(generation uint64) bool {
	m.mu.Lock()
	active := m.active
	m.mu.Unlock()
	if active == nil {
		return false
	}
	return active.revoked(generation)
}

// Active reports the inbound ID of the running platform VPN.
func (m *Manager) Active() (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active == nil {
		return "", false
	}
	return m.active.id, true
}

// Accepter is a netapi.Accepter whose device is a platform VPN interface.
type Accepter struct {
	m    *Manager
	id   string
	open Opener

	// opMu serializes establish, swap and close.
	opMu sync.Mutex

	mu       sync.Mutex
	spec     Spec
	ranges   [2]netip.Prefix
	v4, v6   netip.Prefix
	current  netapi.Accepter
	gen      uint64
	applied  Config
	closed   bool
	kickCh   chan struct{}
	done     chan struct{}
	loopDone chan struct{}
}

// New establishes the platform interface and starts the stack. A failure is
// returned to the inbound runtime and never stops the core.
func (m *Manager) New(id string, spec Spec, ranges [2]netip.Prefix, open Opener) (*Accepter, error) {
	a := &Accepter{m: m, id: id, open: open, spec: spec, ranges: ranges,
		kickCh: make(chan struct{}, 1), done: make(chan struct{}), loopDone: make(chan struct{})}

	m.mu.Lock()
	if m.provider == nil {
		m.mu.Unlock()
		err := &Error{Code: CodeProviderUnavailable, Message: "this platform does not provide a VPN interface"}
		m.fail(id, err)
		return nil, err
	}
	if m.active != nil {
		other := m.active.id
		m.mu.Unlock()
		return nil, &Error{Code: CodeBusy, Message: fmt.Sprintf("platform VPN is already used by inbound %q", other)}
	}
	m.active = a
	m.mu.Unlock()

	if err := a.resolveAddresses(); err != nil {
		m.clearActive(a)
		m.fail(id, err)
		return nil, err
	}

	a.opMu.Lock()
	defer a.opMu.Unlock()
	desired := a.desired()
	m.update(func(s *Status) {
		*s = Status{State: StateEstablishing, InboundID: id, Pending: desired.clone(),
			Reconfigurations: s.Reconfigurations, ReconfigureFailures: s.ReconfigureFailures}
	})
	stack, gen, err := a.establish(desired)
	if err != nil {
		m.clearActive(a)
		m.fail(id, err)
		return nil, err
	}
	a.mu.Lock()
	a.current, a.gen, a.applied = stack, gen, desired
	a.mu.Unlock()
	now := time.Now().UnixMilli()
	m.update(func(s *Status) {
		s.State, s.Generation, s.Applied, s.Pending = StateRunning, gen, desired.clone(), nil
		s.LastError, s.ErrorCode, s.StartedAt = "", "", now
	})
	go a.loop()
	return a, nil
}

func (m *Manager) clearActive(a *Accepter) {
	m.mu.Lock()
	if m.active == a {
		m.active = nil
	}
	m.mu.Unlock()
}

func (m *Manager) fail(id string, err error) {
	m.update(func(s *Status) {
		s.State, s.InboundID, s.Generation, s.Applied, s.Pending = StateFailed, id, 0, nil, nil
		s.LastError, s.ErrorCode = err.Error(), ErrorCode(err)
	})
}

func (a *Accepter) resolveAddresses() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	var err error
	a.v4, err = interfacePrefix(a.spec.Stack.Portal)
	if err != nil {
		return fmt.Errorf("invalid TUN portal: %w", err)
	}
	a.v6, err = interfacePrefix(a.spec.Stack.PortalV6)
	if err != nil {
		return fmt.Errorf("invalid TUN IPv6 portal: %w", err)
	}
	if (!a.v4.IsValid() || !a.v6.IsValid()) && a.m.Addresses != nil {
		v4, v6, err := a.m.Addresses()
		if err != nil {
			return &Error{Code: CodeEstablishFailed, Message: "allocate TUN addresses: " + err.Error()}
		}
		if !a.v4.IsValid() {
			a.v4 = v4
		}
		if !a.v6.IsValid() {
			a.v6 = v6
		}
	}
	if !a.v4.IsValid() {
		a.v4 = netip.MustParsePrefix("172.19.0.1/24")
	}
	return nil
}

func interfacePrefix(s string) (netip.Prefix, error) {
	if s == "" {
		return netip.Prefix{}, nil
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		return p, nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	if addr.Is4() {
		return netip.PrefixFrom(addr, 24), nil
	}
	return netip.PrefixFrom(addr, 64), nil
}

// desired computes the requested configuration from the current spec, the
// active FakeIP pools and the platform revision.
func (a *Accepter) desired() Config {
	a.mu.Lock()
	defer a.mu.Unlock()
	mtu := a.spec.Stack.MTU
	if mtu <= 0 && a.m.DefaultMTU != nil {
		mtu = a.m.DefaultMTU()
	}
	if mtu <= 0 {
		mtu = 1500
	}
	c := Config{MTU: mtu, Routes: normalize(a.spec.Routes), Excludes: normalize(a.spec.Excludes),
		Revision: a.m.currentRevision(), DNS: []string{}, FakeIPRoutes: []string{}, RouteMode: a.spec.RouteMode}
	if c.RouteMode != "" {
		// Like desktop route tables, only families present on the TUN are routed.
		c.Routes = slices.DeleteFunc(c.Routes, func(route string) bool {
			if p, err := netip.ParsePrefix(route); err == nil {
				return (p.Addr().Is4() && !a.v4.IsValid()) || (p.Addr().Is6() && (!a.v6.IsValid() || !configuration.IPv6.Load()))
			}
			return false
		})
	}
	if a.v4.IsValid() {
		c.IPv4, c.IPv4Prefix = a.v4.Addr().String(), a.v4.Bits()
		c.DNS = append(c.DNS, a.v4.Addr().Next().String())
	}
	if a.v6.IsValid() {
		c.IPv6, c.IPv6Prefix = a.v6.Addr().String(), a.v6.Bits()
		c.DNS = append(c.DNS, a.v6.Addr().Next().String())
	}
	if a.spec.AutoFakeIPRoute {
		for _, p := range a.ranges {
			if !p.IsValid() || (p.Addr().Is6() && !configuration.IPv6.Load()) {
				continue
			}
			c.FakeIPRoutes = append(c.FakeIPRoutes, p.Masked().String())
		}
	}
	return c
}

func normalize(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func (a *Accepter) stackConfig(fd int, c Config) device.TunConfig {
	a.mu.Lock()
	defer a.mu.Unlock()
	o := a.spec.Stack
	o.Name = fmt.Sprintf("fd://%d", fd)
	o.MTU = c.MTU
	// The platform installs routes; the stack must not manage OS routes.
	o.AutoFakeIPRoute = false
	o.PostUp, o.PostDown = nil, nil
	o.FakeIPRanges = a.ranges
	o.Portal = a.v4.String()
	if a.v6.IsValid() {
		o.PortalV6 = a.v6.String()
	} else {
		o.PortalV6 = ""
	}
	return o
}

// establish creates a new generation and starts a stack on it. On failure the
// new generation is released and the error carries a stable code.
func (a *Accepter) establish(c Config) (netapi.Accepter, uint64, error) {
	provider := a.m.Provider()
	if provider == nil {
		return nil, 0, &Error{Code: CodeProviderUnavailable, Message: "platform VPN provider is not registered"}
	}
	gen := a.m.generation.Add(1)
	timeout := a.m.EstablishTimeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	fd, err := provider.Establish(ctx, gen, c)
	cancel()
	if err != nil {
		provider.Release(gen)
		return nil, 0, err
	}
	if fd < 0 {
		provider.Release(gen)
		return nil, 0, &Error{Code: CodeEstablishFailed, Message: "platform returned an invalid descriptor"}
	}
	stack, err := a.open(a.stackConfig(fd, c))
	if err != nil {
		provider.Release(gen)
		return nil, 0, &Error{Code: CodeStackFailed, Message: err.Error()}
	}
	return stack, gen, nil
}

func (a *Accepter) kick() {
	select {
	case a.kickCh <- struct{}{}:
	default:
	}
}

func (a *Accepter) loop() {
	defer close(a.loopDone)
	for {
		select {
		case <-a.done:
			return
		case <-a.kickCh:
		}
		// Coalesce bursts: wait, then drain kicks that arrived meanwhile.
		if d := a.m.Debounce; d > 0 {
			select {
			case <-a.done:
				return
			case <-time.After(d):
			}
		}
		select {
		case <-a.kickCh:
		default:
		}
		if err := a.Apply(); err != nil {
			log.Warn("platform VPN reconfiguration failed", "inbound", a.id, "err", err)
		}
	}
}

// UpdateFakeIPRanges records the active pools and schedules a coalesced
// reconfiguration. The inbound runtime calls it without rebuilding listeners.
func (a *Accepter) UpdateFakeIPRanges(ranges [2]netip.Prefix) error {
	a.mu.Lock()
	changed := a.ranges != ranges
	a.ranges = ranges
	a.mu.Unlock()
	if changed {
		a.kick()
	}
	return nil
}

// Reconfigure replaces the inbound spec in place and applies it immediately,
// keeping the core, its listeners and the old interface until the new one is
// ready.
func (a *Accepter) Reconfigure(spec Spec) error {
	a.mu.Lock()
	a.spec = spec
	a.mu.Unlock()
	if err := a.resolveAddresses(); err != nil {
		return err
	}
	return a.Apply()
}

// Apply applies the desired configuration if it differs from the applied one.
func (a *Accepter) Apply() error {
	a.opMu.Lock()
	defer a.opMu.Unlock()
	a.mu.Lock()
	closed, applied, oldGen, old := a.closed, a.applied, a.gen, a.current
	a.mu.Unlock()
	if closed || old == nil {
		return nil
	}
	desired := a.desired()
	if desired.Equal(applied) {
		return nil
	}
	a.m.update(func(s *Status) { s.State, s.Pending = StateReconfiguring, desired.clone() })
	started := time.Now()
	// Make before break: the old stack keeps running until the new interface
	// and stack exist. Android replaces its interface during establish(), so
	// in-flight TCP sessions of the old stack may still reset.
	stack, gen, err := a.establish(desired)
	if err != nil {
		// A refused Builder.establish() leaves the previous interface intact.
		a.m.update(func(s *Status) {
			s.State, s.Pending, s.LastError, s.ErrorCode = StateRunning, nil, err.Error(), ErrorCode(err)
			s.ReconfigureFailures++
		})
		if ErrorCode(err) == CodeStackFailed {
			return a.recoverLocked(applied, err)
		}
		return err
	}
	a.mu.Lock()
	a.current, a.gen, a.applied = stack, gen, desired
	a.mu.Unlock()
	closeErr := old.Close()
	a.m.Provider().Release(oldGen)
	elapsed := time.Since(started).Milliseconds()
	a.m.update(func(s *Status) {
		s.State, s.Generation, s.Applied, s.Pending = StateRunning, gen, desired.clone(), nil
		s.LastError, s.ErrorCode = "", ""
		s.Reconfigurations++
		s.LastReconfigureAt, s.LastSwitchMillis = time.Now().UnixMilli(), elapsed
	})
	log.Info("platform VPN reconfigured", "inbound", a.id, "generation", gen, "switch_ms", elapsed)
	if closeErr != nil {
		log.Warn("close previous platform TUN stack failed", "err", closeErr)
	}
	return nil
}

// recoverLocked restores the last applied configuration after a stack start
// failure, because the platform may already have replaced the interface.
func (a *Accepter) recoverLocked(applied Config, cause error) error {
	a.mu.Lock()
	old, oldGen := a.current, a.gen
	a.mu.Unlock()
	stack, gen, err := a.establish(applied)
	if err != nil {
		_ = old.Close()
		a.m.Provider().Release(oldGen)
		a.mu.Lock()
		a.current, a.gen = nil, 0
		a.mu.Unlock()
		err = errors.Join(cause, fmt.Errorf("restore previous VPN configuration: %w", err))
		a.m.update(func(s *Status) {
			s.State, s.Generation, s.Applied, s.Pending = StateFailed, 0, nil, nil
			s.LastError, s.ErrorCode = err.Error(), ErrorCode(cause)
		})
		return err
	}
	a.mu.Lock()
	a.current, a.gen = stack, gen
	a.mu.Unlock()
	_ = old.Close()
	a.m.Provider().Release(oldGen)
	a.m.update(func(s *Status) { s.Generation, s.State = gen, StateRunning })
	return cause
}

func (a *Accepter) revoked(generation uint64) bool {
	a.opMu.Lock()
	defer a.opMu.Unlock()
	a.mu.Lock()
	if a.closed || a.current == nil || a.gen != generation {
		a.mu.Unlock()
		return false
	}
	current, gen := a.current, a.gen
	a.current, a.gen = nil, 0
	a.mu.Unlock()
	_ = current.Close()
	a.m.Provider().Release(gen)
	a.m.update(func(s *Status) {
		s.State, s.Generation, s.Applied, s.Pending = StateRevoked, 0, nil, nil
		s.LastError, s.ErrorCode = "VPN permission was revoked by the system or another VPN app", CodeRevoked
	})
	return true
}

// Close stops the stack and releases the platform interface. It is idempotent.
func (a *Accepter) Close() error {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil
	}
	a.closed = true
	close(a.done)
	a.mu.Unlock()
	<-a.loopDone

	a.opMu.Lock()
	defer a.opMu.Unlock()
	a.mu.Lock()
	current, gen := a.current, a.gen
	a.current, a.gen = nil, 0
	a.mu.Unlock()
	var err error
	if current != nil {
		a.m.update(func(s *Status) { s.State = StateStopping })
		err = current.Close()
		if p := a.m.Provider(); p != nil {
			p.Release(gen)
		}
	}
	a.m.clearActive(a)
	a.m.update(func(s *Status) {
		if s.State == StateRevoked || s.State == StateFailed {
			return // keep the reason visible
		}
		s.State, s.Generation, s.Applied, s.Pending = StateStopped, 0, nil, nil
		s.LastError, s.ErrorCode = "", ""
	})
	return err
}

func (a *Accepter) Interface() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.current == nil {
		return ""
	}
	return a.current.Interface()
}

// Generation returns the generation of the running interface, or zero.
func (a *Accepter) Generation() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.gen
}

func (a *Accepter) StackDiagnostic(limit int) lightweight.StackDiagnostics {
	a.mu.Lock()
	current := a.current
	a.mu.Unlock()
	if r, ok := current.(interface {
		StackDiagnostic(int) lightweight.StackDiagnostics
	}); ok {
		return r.StackDiagnostic(limit)
	}
	return lightweight.StackDiagnostics{}
}

func (a *Accepter) TrafficControlQueue() (trafficcontrol.FairStats, bool) {
	a.mu.Lock()
	current := a.current
	a.mu.Unlock()
	if r, ok := current.(trafficcontrol.QueueReporter); ok {
		return r.TrafficControlQueue()
	}
	return trafficcontrol.FairStats{}, false
}
