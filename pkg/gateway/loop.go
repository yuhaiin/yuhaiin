package gateway

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
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
		if host == dstHost || ((host == "" || listenIP.IsUnspecified()) && localDestination(dstHost, dstIP)) || (listenIP.IsLoopback() && (dstIP.IsLoopback() || dstHost == "localhost")) {
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
	host, process        string
	port                 uint16
	source               netip.Addr
}

// Hostname aliases are caught by actual socket reentry tracking. Never resolve
// arbitrary remote names just to compare them with a wildcard listener.
func localDestination(host string, ip netip.Addr) bool {
	if host == "localhost" || ip.IsLoopback() || ip.IsUnspecified() {
		return true
	}
	if !ip.IsValid() {
		return false
	}
	addresses, _ := net.InterfaceAddrs()
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err == nil && prefix.Addr().Unmap() == ip.Unmap() {
			return true
		}
	}
	return false
}

func sessionAllowed(s *snapshot, session interceptSession) bool {
	g := s.gateways[session.gatewayID]
	if g == nil || !g.engine.config.Enabled {
		return false
	}
	for _, i := range s.interceptions {
		if i.config.GatewayID == session.gatewayID && i.config.InboundID == session.inboundID {
			if !matchesDomains(session.host, i.config.Domains, i.config.ExcludeDomains) ||
				(len(i.config.Ports) > 0 && !slices.Contains(i.config.Ports, session.port)) ||
				(len(i.config.Processes) > 0 && !slices.Contains(i.config.Processes, session.process)) {
				return false
			}
			if len(i.sources) > 0 {
				matched := false
				for _, prefix := range i.sources {
					matched = matched || prefix.Contains(session.source)
				}
				if !matched {
					return false
				}
			}
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
