package netlink

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/log"
)

// SystemRoute is one destination route owned by the System Network Manager.
// Link is the runtime interface index. Gateway is the next hop for broadcast
// interfaces; it stays invalid for point-to-point interfaces and TUNs.
type SystemRoute struct {
	Prefix  netip.Prefix
	Link    int
	Gateway netip.Addr
}

func (r SystemRoute) String() string {
	if r.Gateway.IsValid() {
		return fmt.Sprintf("%s via %s dev #%d", r.Prefix, r.Gateway, r.Link)
	}
	return fmt.Sprintf("%s dev #%d", r.Prefix, r.Link)
}

// ErrRouteConflict reports that another program already owns a route for the
// same prefix. Backends wrap it so the manager can let that route win.
var ErrRouteConflict = errors.New("route already exists on another interface")

// ErrRoutesUnsupported is returned on platforms without system route control.
var ErrRoutesUnsupported = errors.New("system route management is not supported on this platform")

// routeBackend never replaces a route it does not own. Add reports whether
// this process created the route; an identical preexisting route may be used
// but is never deleted.
type routeBackend interface {
	Add(SystemRoute) (owned bool, err error)
	Delete(SystemRoute) error
	// Close releases auxiliary state (policy rules) once no routes remain.
	Close() error
}

// routeReplacer atomically changes the target of an owned route.
type routeReplacer interface {
	Replace(old, new SystemRoute) error
}

type installedRoute struct {
	route SystemRoute
	owned bool
}

// RouteManager is the single owner of the system routes Yuhaiin installs. It
// applies a desired set as a diff: new and changed routes first, then removal
// of obsolete ones. A failed addition rolls back the routes this update added
// or changed, so the previous set stays in effect. Failed deletions stay
// tracked and are retried by the next update or Close.
type RouteManager struct {
	mu        sync.Mutex
	backend   routeBackend
	installed map[netip.Prefix]installedRoute
	conflicts []netip.Prefix
	closed    bool
}

func newRouteManager(backend routeBackend) *RouteManager {
	return &RouteManager{backend: backend, installed: make(map[netip.Prefix]installedRoute)}
}

// NewRouteManager returns the platform route manager, or ErrRoutesUnsupported.
func NewRouteManager() (*RouteManager, error) {
	backend, err := newPlatformRouteBackend()
	if err != nil {
		return nil, err
	}
	return newRouteManager(backend), nil
}

// Update makes the installed routes equal to desired. Prefixes must be unique.
// Prefixes another program already routes are skipped and returned as
// conflicts; they are retried by every update (for example after a network
// change), and the other program's route keeps priority meanwhile.
func (m *RouteManager) Update(desired []SystemRoute) (conflicts []netip.Prefix, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, errors.New("system route manager is closed")
	}
	want := make(map[netip.Prefix]SystemRoute, len(desired))
	for _, r := range desired {
		r.Prefix = r.Prefix.Masked()
		if !r.Prefix.IsValid() || r.Link <= 0 {
			return nil, fmt.Errorf("invalid system route %s", r)
		}
		if previous, ok := want[r.Prefix]; ok && previous != r {
			return nil, fmt.Errorf("prefix %s is assigned to two targets", r.Prefix)
		}
		want[r.Prefix] = r
	}
	type change struct {
		prefix   netip.Prefix
		previous *installedRoute
	}
	var changes []change
	rollback := func(cause error) error {
		for i := len(changes) - 1; i >= 0; i-- {
			c := changes[i]
			current := m.installed[c.prefix]
			if c.previous == nil {
				cause = errors.Join(cause, m.remove(c.prefix))
				continue
			}
			if err := m.change(current.route, c.previous.route); err != nil {
				cause = errors.Join(cause, fmt.Errorf("restore route %s: %w", c.previous.route, err))
				continue
			}
			m.installed[c.prefix] = *c.previous
		}
		return cause
	}
	for _, p := range sortedPrefixes(want) {
		r := want[p]
		current, ok := m.installed[p]
		if ok && current.route == r {
			continue
		}
		if ok && current.owned {
			if err := m.change(current.route, r); err != nil {
				return nil, rollback(fmt.Errorf("change route %s: %w", r, err))
			}
			previous := current
			m.installed[p] = installedRoute{route: r, owned: true}
			changes = append(changes, change{p, &previous})
			continue
		}
		if ok {
			// A borrowed route is not ours to change; forget it and add anew.
			delete(m.installed, p)
		}
		owned, err := m.backend.Add(r)
		if errors.Is(err, ErrRouteConflict) {
			conflicts = append(conflicts, p)
			continue
		}
		if err != nil {
			return nil, rollback(fmt.Errorf("add route %s: %w", r, err))
		}
		m.installed[p] = installedRoute{route: r, owned: owned}
		changes = append(changes, change{prefix: p})
	}
	if len(conflicts) != 0 && !slices.Equal(conflicts, m.conflicts) {
		log.Warn("system routes skipped because other programs already route them", "count", len(conflicts), "prefixes", firstPrefixes(conflicts, 16))
	}
	m.conflicts = conflicts
	for _, p := range sortedPrefixes(m.installed) {
		if _, ok := want[p]; !ok {
			err = errors.Join(err, m.remove(p))
		}
	}
	return slices.Clone(conflicts), err
}

func (m *RouteManager) change(old, new SystemRoute) error {
	if replacer, ok := m.backend.(routeReplacer); ok {
		return replacer.Replace(old, new)
	}
	if err := m.backend.Delete(old); err != nil {
		return err
	}
	_, err := m.backend.Add(new)
	return err
}

func (m *RouteManager) remove(p netip.Prefix) error {
	r := m.installed[p]
	if r.owned {
		if err := m.backend.Delete(r.route); err != nil {
			return fmt.Errorf("delete route %s: %w", r.route, err)
		}
	}
	delete(m.installed, p)
	return nil
}

// Installed returns the routes currently tracked, sorted by prefix.
func (m *RouteManager) Installed() []SystemRoute {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]SystemRoute, 0, len(m.installed))
	for _, p := range sortedPrefixes(m.installed) {
		out = append(out, m.installed[p].route)
	}
	return out
}

// Close deletes every owned route and releases auxiliary state. Calling it
// again retries failed deletions.
func (m *RouteManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	var err error
	for _, p := range sortedPrefixes(m.installed) {
		err = errors.Join(err, m.remove(p))
	}
	if len(m.installed) == 0 {
		err = errors.Join(err, m.backend.Close())
	}
	return err
}

func sortedPrefixes[V any](m map[netip.Prefix]V) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(m))
	for p := range m {
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b netip.Prefix) int {
		if n := a.Addr().Compare(b.Addr()); n != 0 {
			return n
		}
		return a.Bits() - b.Bits()
	})
	return out
}

func firstPrefixes(prefixes []netip.Prefix, limit int) []string {
	out := make([]string, 0, min(limit, len(prefixes)))
	for _, p := range prefixes[:min(limit, len(prefixes))] {
		out = append(out, p.String())
	}
	return out
}
