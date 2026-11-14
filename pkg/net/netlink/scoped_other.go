//go:build !darwin

package netlink

// ScopedRouteManager exists only on macOS; elsewhere protected sockets do
// not depend on interface-scoped routes.
type ScopedRouteManager struct{}

func NewScopedRouteManager(func(string) bool) *ScopedRouteManager { return nil }

func (*ScopedRouteManager) Reconcile() error               { return nil }
func (*ScopedRouteManager) Routes() ([]ScopedRoute, error) { return nil, nil }
func (*ScopedRouteManager) Close() error                   { return nil }
