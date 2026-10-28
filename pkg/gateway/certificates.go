package gateway

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
)

func WithManagedCertificates(resolve func(context.Context, []string) (*tls.Config, error)) Option {
	return func(m *Manager) { m.managedCertificates = resolve }
}

func WithACMEHTTP01(serve func(string, http.ResponseWriter, *http.Request) bool) Option {
	return func(m *Manager) { m.serveACMEHTTP01 = serve }
}

// HTTP01Available describes an actual published, administrator-enabled port-80
// listener. No ACME operation binds a socket or alters listener/access settings.
func (m *Manager) HTTP01Available(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return false
	}
	s := m.current.Load()
	if s == nil {
		return false
	}
	entry := s.gateways[id]
	if entry == nil {
		return false
	}
	g := entry.engine.config
	_, port, err := net.SplitHostPort(g.Listen)
	return err == nil && port == "80" && g.Enabled && g.ACMEHTTP01 && entry.tls == nil && s.listeners[g.Listen] == entry
}
