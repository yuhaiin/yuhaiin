package processnet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/yuhaiin/sessionnet"
)

// HostLoopbackMapping forwards one loopback endpoint of an isolated session
// (127.0.0.1:port or [::1]:port inside the session network namespace) to a
// loopback endpoint of the network namespace Yuhaiin itself runs in. The
// families are independent: [::1]:8080 may forward to 127.0.0.1:8080.
type HostLoopbackMapping struct {
	// Network is "tcp" or "udp".
	Network string
	Session netip.AddrPort
	Host    netip.AddrPort
}

func (m HostLoopbackMapping) String() string {
	return fmt.Sprintf("%s %s -> %s", m.Network, m.Session, m.Host)
}

// HostLoopbackForwards converts mappings into the session forwards that
// reserve their session endpoints.
func HostLoopbackForwards(mappings []HostLoopbackMapping) []sessionnet.LoopbackForward {
	out := make([]sessionnet.LoopbackForward, len(mappings))
	for i, m := range mappings {
		out[i] = sessionnet.LoopbackForward{Network: m.Network, Address: m.Session}
	}
	return out
}

// HostLoopbackFlow describes one forwarded connection or UDP flow, for the
// dialer and for connection accounting.
type HostLoopbackFlow struct {
	Mapping HostLoopbackMapping
	// Source is the session process's own socket address (a loopback
	// address of the session).
	Source    netip.AddrPort
	InboundID string
	// Process, PID and UID identify the session process when sock_diag
	// could resolve it.
	Process  string
	PID, UID uint
}

// HostLoopbackDialer opens the host side of forwarded flows. It must create
// its sockets in Yuhaiin's own network namespace and must never route them
// through an outbound or back into a session.
type HostLoopbackDialer interface {
	DialTCP(context.Context, HostLoopbackFlow) (net.Conn, error)
	// ListenUDP returns an unconnected socket on the host loopback of the
	// mapping's host family; the forwarder writes to and accepts replies
	// from Mapping.Host only.
	ListenUDP(context.Context, HostLoopbackFlow) (net.PacketConn, error)
}

// ValidateHostLoopbackMappings checks mappings at the runtime boundary: the
// session side must be exactly 127.0.0.1 or ::1, the host side a loopback
// address, ports must be set and (network, session endpoint) unique.
func ValidateHostLoopbackMappings(mappings []HostLoopbackMapping) error {
	seen := make(map[[2]string]bool, len(mappings))
	for _, m := range mappings {
		if m.Network != "tcp" && m.Network != "udp" {
			return fmt.Errorf("host loopback mapping %s: protocol must be tcp or udp", m)
		}
		if a := m.Session.Addr(); a != netip.AddrFrom4([4]byte{127, 0, 0, 1}) && a != netip.IPv6Loopback() {
			return fmt.Errorf("host loopback mapping %s: session address must be 127.0.0.1 or ::1", m)
		}
		if a := m.Host.Addr(); !a.IsValid() || a.Is4In6() || !a.IsLoopback() {
			return fmt.Errorf("host loopback mapping %s: host address must be a loopback address", m)
		}
		if m.Session.Port() == 0 || m.Host.Port() == 0 {
			return fmt.Errorf("host loopback mapping %s: ports must be 1-65535", m)
		}
		key := [2]string{m.Network, m.Session.String()}
		if seen[key] {
			return fmt.Errorf("host loopback mapping %s: duplicate session endpoint", m)
		}
		seen[key] = true
	}
	return nil
}

// DirectHostLoopbackDialer opens plain sockets in the calling process's
// network namespace with an explicit address family. It refuses anything but
// loopback targets.
type DirectHostLoopbackDialer struct {
	Timeout time.Duration
}

var errNotLoopback = errors.New("host loopback forwarding: target is not a loopback address")

func family(network string, addr netip.Addr) string {
	if addr.Is4() {
		return network + "4"
	}
	return network + "6"
}

func (d DirectHostLoopbackDialer) DialTCP(ctx context.Context, flow HostLoopbackFlow) (net.Conn, error) {
	host := flow.Mapping.Host
	if !host.Addr().IsLoopback() {
		return nil, errNotLoopback
	}
	dialer := net.Dialer{Timeout: d.Timeout}
	return dialer.DialContext(ctx, family("tcp", host.Addr()), host.String())
}

func (d DirectHostLoopbackDialer) ListenUDP(_ context.Context, flow HostLoopbackFlow) (net.PacketConn, error) {
	host := flow.Mapping.Host
	if !host.Addr().IsLoopback() {
		return nil, errNotLoopback
	}
	local := netip.AddrFrom4([4]byte{127, 0, 0, 1})
	if host.Addr().Is6() {
		local = netip.IPv6Loopback()
	}
	return net.ListenUDP(family("udp", host.Addr()), net.UDPAddrFromAddrPort(netip.AddrPortFrom(local, 0)))
}
