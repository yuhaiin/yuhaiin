//go:build !(linux && !android)

package forward

// Manager reports forwarding as unsupported outside Linux.
type Manager struct{ Sysctl *Sysctl }

func New() *Manager { return &Manager{Sysctl: &Sysctl{}} }

// Supported reports whether this platform has a forwarding applier.
func Supported() bool { return false }

func (m *Manager) Apply(plan Plan) error {
	if plan.IPv4 || plan.IPv6 || len(plan.Rules) != 0 {
		return ErrUnsupported
	}
	return nil
}

func (m *Manager) Close() error { return nil }
