package netlink

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/log"
)

// NormalizeRoutes removes duplicates and contained prefixes without joining
// adjacent networks. The covered addresses are unchanged.
func NormalizeRoutes(routes []netip.Prefix) []netip.Prefix {
	var normalized []netip.Prefix
	for _, p := range routes {
		if p.IsValid() {
			normalized = append(normalized, p.Masked())
		}
	}
	slices.SortFunc(normalized, func(a, b netip.Prefix) int {
		if n := a.Addr().Compare(b.Addr()); n != 0 {
			return n
		}
		return a.Bits() - b.Bits()
	})
	result := normalized[:0]
	for _, p := range normalized {
		if len(result) > 0 && result[len(result)-1].Contains(p.Addr()) && result[len(result)-1].Bits() <= p.Bits() {
			continue
		}
		result = append(result, p)
	}
	return result
}

// routeBackend never replaces an existing route. Add reports whether this
// process created it; matching preexisting routes may be used but not deleted.
type routeBackend interface {
	Add(netip.Prefix) (bool, error)
	Delete(netip.Prefix) error
	Close(routesPending bool) error
}

// RouteManager tracks the routes installed for one TUN, including failed
// deletions, so an update or repeated Close can retry their cleanup.
type RouteManager struct {
	mu        sync.Mutex
	backend   routeBackend
	installed map[netip.Prefix]bool
	required  []netip.Prefix
	closed    bool
}

func newRouteManager(backend routeBackend) *RouteManager {
	return &RouteManager{backend: backend, installed: make(map[netip.Prefix]bool)}
}

func (m *RouteManager) Update(routes []netip.Prefix) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errors.New("TUN route manager is closed")
	}
	desired := make(map[netip.Prefix]bool)
	var added []netip.Prefix
	for _, p := range NormalizeRoutes(append(slices.Clone(routes), m.required...)) {
		desired[p] = true
		if _, ok := m.installed[p]; ok {
			continue
		}
		owned, err := m.backend.Add(p)
		if err != nil {
			result := fmt.Errorf("add TUN route %s: %w", p, err)
			for _, previous := range added {
				result = errors.Join(result, m.remove(previous))
			}
			return result
		}
		m.installed[p] = owned
		added = append(added, p)
	}
	var err error
	for _, p := range m.prefixes() {
		if !desired[p] {
			err = errors.Join(err, m.remove(p))
		}
	}
	return err
}

func (m *RouteManager) prefixes() []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(m.installed))
	for p := range m.installed {
		prefixes = append(prefixes, p)
	}
	slices.SortFunc(prefixes, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
	return prefixes
}

func (m *RouteManager) remove(p netip.Prefix) error {
	if m.installed[p] {
		if err := m.backend.Delete(p); err != nil {
			return fmt.Errorf("delete TUN route %s: %w", p, err)
		}
	}
	delete(m.installed, p)
	return nil
}

func (m *RouteManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	var err error
	for _, p := range m.prefixes() {
		err = errors.Join(err, m.remove(p))
	}
	// Restore auxiliary state (e.g. system DNS) even if deletion failed.
	// The Linux backend retains policy rule leases until all routes are gone.
	err = errors.Join(err, m.backend.Close(len(m.installed) != 0))
	return err
}

func installRoutes(opt *Options, backend routeBackend, required ...netip.Prefix) (func(), error) {
	manager := newRouteManager(backend)
	manager.required = required
	opt.RouteManager = manager
	cleanup := func() {
		if err := manager.Close(); err != nil {
			log.Error("clean up TUN routes failed", "interface", opt.Interface.Name, "err", err)
		}
	}
	return cleanup, manager.Update(opt.RoutesForFamilies(opt.Routes))
}

// RoutesForFamilies excludes routes for address families unavailable on the TUN.
func (o *Options) RoutesForFamilies(routes []netip.Prefix) []netip.Prefix {
	var result []netip.Prefix
	for _, p := range routes {
		if p.IsValid() && ((p.Addr().Is4() && o.V4Address().IsValid()) || (p.Addr().Is6() && o.V6Address().IsValid())) {
			result = append(result, p)
		}
	}
	return result
}
