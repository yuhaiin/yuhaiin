package gateway

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type listenerRuntime struct {
	raw         net.Listener
	server      *http.Server
	mu          sync.Mutex
	closed      bool
	connections map[*listenerConn]struct{}
	gatewayID   string
}
type listenerConn struct {
	net.Conn
	owner *listenerRuntime
}

func (c *listenerConn) Close() error {
	err := c.Conn.Close()
	c.owner.mu.Lock()
	delete(c.owner.connections, c)
	c.owner.mu.Unlock()
	return err
}
func (l *listenerRuntime) track(c net.Conn) net.Conn {
	wrapped := &listenerConn{Conn: c, owner: l}
	l.mu.Lock()
	if !l.closed {
		l.connections[wrapped] = struct{}{}
	}
	closed := l.closed
	l.mu.Unlock()
	if closed {
		_ = wrapped.Close()
	}
	return wrapped
}
func (l *listenerRuntime) close() {
	l.mu.Lock()
	l.closed = true
	connections := make([]*listenerConn, 0, len(l.connections))
	for conn := range l.connections {
		connections = append(connections, conn)
	}
	l.mu.Unlock()
	_ = l.server.Close()
	_ = l.raw.Close()
	// Server.Close excludes hijacked connections. Track physical sockets below
	// TLS so both net/http's concrete *tls.Conn and upgraded lifetimes survive.
	for _, conn := range connections {
		_ = conn.Close()
	}
}

func (l *listenerRuntime) reassign(gatewayID string) {
	if l.gatewayID == gatewayID {
		return
	}
	l.gatewayID = gatewayID
	l.mu.Lock()
	connections := make([]*listenerConn, 0, len(l.connections))
	for conn := range l.connections {
		connections = append(connections, conn)
	}
	l.mu.Unlock()
	for _, conn := range connections {
		_ = conn.Close()
	}
}

type selectedListener struct {
	net.Listener
	selectTLS func() (*tls.Config, bool)
	track     func(net.Conn) net.Conn
}

func (l selectedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	c = l.track(c)
	config, ok := l.selectTLS()
	if !ok {
		_ = c.Close()
		return nil, net.ErrClosed
	}
	if config != nil {
		return tls.Server(c, config), nil
	}
	return c, nil
}

func (m *Manager) stageListeners(s *snapshot) (map[string]*listenerRuntime, error) {
	staged := make(map[string]*listenerRuntime)
	for address := range s.listeners {
		if m.listeners[address] != nil {
			continue
		}
		lis, err := net.Listen("tcp", address)
		if err != nil {
			for _, l := range staged {
				_ = l.raw.Close()
			}
			return nil, fmt.Errorf("listen %s: %w", address, err)
		}
		protocols := new(http.Protocols)
		protocols.SetHTTP1(true)
		protocols.SetHTTP2(true)
		server := &http.Server{ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 1 << 20, Protocols: protocols, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}}}
		server.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
			state := netapi.WithContext(ctx)
			state.Source = c.RemoteAddr()
			state.Destination = c.LocalAddr()
			state.SetInbound(c.LocalAddr())
			return state
		}
		server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if m.internalSource(netapi.GetContext(r.Context()).Source) {
				http.Error(w, "gateway loop rejected", http.StatusLoopDetected)
				return
			}
			entry := m.current.Load().listeners[address]
			if entry == nil {
				http.Error(w, "gateway disabled", http.StatusServiceUnavailable)
				return
			}
			peer, err := netip.ParseAddrPort(r.RemoteAddr)
			if err != nil {
				http.Error(w, "invalid peer", http.StatusForbidden)
				return
			}
			allowed := len(entry.sources) == 0 && peer.Addr().IsLoopback()
			for _, prefix := range entry.sources {
				allowed = allowed || prefix.Contains(peer.Addr().Unmap())
			}
			if !allowed {
				http.Error(w, "source denied", http.StatusForbidden)
				return
			}
			if entry.engine.config.ACMEHTTP01 && m.serveACMEHTTP01 != nil && m.serveACMEHTTP01(entry.engine.config.ID, w, r) {
				return
			}
			state := netapi.ForkContext(r.Context())
			state.SetInboundID("gateway:" + entry.engine.config.ID).SetInboundName(entry.engine.config.Name)
			if entry.engine.policy.needsProcess && m.lookupProcess != nil {
				if address, err := netapi.ParseSysAddr(state.Destination); err == nil {
					m.lookupProcess(state, address)
				}
			}
			entry.engine.ServeHTTP(w, r.WithContext(state))
		})
		staged[address] = &listenerRuntime{raw: lis, server: server, connections: make(map[*listenerConn]struct{}), gatewayID: s.listeners[address].engine.config.ID}
	}
	return staged, nil
}

func (m *Manager) publishListeners(staged map[string]*listenerRuntime, s *snapshot) {
	for _, g := range s.gateways {
		g.engine.startHealth()
	}
	for address, l := range staged {
		m.listeners[address] = l
		go func() {
			_ = l.server.Serve(selectedListener{l.raw, func() (*tls.Config, bool) {
				entry := m.current.Load().listeners[address]
				if entry == nil {
					return nil, false
				}
				return entry.tls, true
			}, l.track})
		}()
	}
	for address, l := range m.listeners {
		if s.listeners[address] == nil {
			l.close()
			delete(m.listeners, address)
		} else {
			l.reassign(s.listeners[address].engine.config.ID)
		}
	}
	m.closeSessions(s)
}
