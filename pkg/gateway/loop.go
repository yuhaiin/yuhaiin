package gateway

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type trackedProxy struct {
	netapi.Proxy
	manager *Manager
}

func (p trackedProxy) Conn(ctx context.Context, a netapi.Address) (net.Conn, error) {
	c, err := p.Proxy.Conn(ctx, a)
	if err != nil {
		return nil, err
	}
	key, err := netip.ParseAddrPort(c.LocalAddr().String())
	if err != nil {
		return c, nil
	}
	key = netip.AddrPortFrom(key.Addr().Unmap(), key.Port())
	p.manager.internalConnections.Store(key, struct{}{})
	return &trackedConn{Conn: c, release: sync.OnceFunc(func() { p.manager.internalConnections.Delete(key) })}, nil
}

type trackedConn struct {
	net.Conn
	release func()
}

func (c *trackedConn) Close() error { err := c.Conn.Close(); c.release(); return err }
func (m *Manager) internalSource(source net.Addr) bool {
	if source == nil {
		return false
	}
	key, err := netip.ParseAddrPort(source.String())
	if err != nil {
		return false
	}
	key = netip.AddrPortFrom(key.Addr().Unmap(), key.Port())
	_, ok := m.internalConnections.Load(key)
	return ok
}
func (m *Manager) selectForRequest(ctx context.Context, a netapi.Address, t route.Target) (Selection, error) {
	// Reject configured listeners even when a different inbound led here.
	// Existing Route loop/process checks still run in the supplied selector.
	for address := range m.current.Load().listeners {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			continue
		}
		dstHost, dstPort, err := net.SplitHostPort(a.String())
		if err != nil || dstPort != port {
			continue
		}
		listenIP, _ := netip.ParseAddr(host)
		dstIP, _ := netip.ParseAddr(dstHost)
		if host == dstHost || listenIP.IsUnspecified() || (listenIP.IsLoopback() && (dstIP.IsLoopback() || dstHost == "localhost")) {
			return Selection{}, errors.New("gateway listener loop rejected")
		}
	}
	if m.selectOutbound == nil {
		return Selection{}, errors.New("outbound selection unavailable")
	}
	s, err := m.selectOutbound(ctx, a, t)
	if err != nil {
		return s, err
	}
	s.Proxy = trackedProxy{Proxy: s.Proxy, manager: m}
	return s, nil
}

type interceptSession struct {
	gatewayID, inboundID string
	mitm                 bool
}

func sessionAllowed(s *snapshot, session interceptSession) bool {
	g := s.gateways[session.gatewayID]
	if g == nil || !g.engine.config.Enabled {
		return false
	}
	for _, i := range s.interceptions {
		if i.config.GatewayID == session.gatewayID && i.config.InboundID == session.inboundID {
			if session.mitm {
				return i.config.Mode == "https_mitm"
			}
			return i.config.Mode == "http_only" || i.config.Mode == "https_mitm"
		}
	}
	return false
}
func (m *Manager) closeSessions(s *snapshot) {
	m.sessionsMu.Lock()
	defer m.sessionsMu.Unlock()
	for conn, session := range m.sessions {
		if !sessionAllowed(s, session) {
			_ = conn.Close()
		}
	}
}
