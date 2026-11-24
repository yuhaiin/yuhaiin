package app

import (
	"context"
	"errors"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/processnet"
	"github.com/Asutorufa/yuhaiin/pkg/statistics"
)

// HostLoopbackComponent marks forwarded SSH host loopback flows in the
// connection list and history.
const HostLoopbackComponent = "ssh-host-loopback"

// hostLoopbackDialer opens the host side of SSH host loopback forwarding in
// Yuhaiin's own network namespace and records each flow like any other
// connection. It deliberately bypasses routing: the destination is a fixed
// loopback service, so no rule may send it to an outbound, and nothing it
// opens can enter a session TUN.
type hostLoopbackDialer struct {
	connections *statistics.Connections
	direct      processnet.DirectHostLoopbackDialer
}

func (d hostLoopbackDialer) context(ctx context.Context, flow processnet.HostLoopbackFlow) *netapi.Context {
	store := netapi.WithContext(ctx)
	if flow.Mapping.Network == "udp" {
		store.Source = net.UDPAddrFromAddrPort(flow.Source)
		store.Destination = net.UDPAddrFromAddrPort(flow.Mapping.Session)
		store.ConnOptions().SetIsUdp(true)
	} else {
		store.Source = net.TCPAddrFromAddrPort(flow.Source)
		store.Destination = net.TCPAddrFromAddrPort(flow.Mapping.Session)
	}
	store.SetInboundID(flow.InboundID)
	store.SetComponent(HostLoopbackComponent)
	store.NodeName = "host loopback"
	if flow.Process != "" || flow.PID != 0 {
		store.SetProcess(flow.Process, flow.PID, flow.UID)
	}
	return store
}

func (d hostLoopbackDialer) DialTCP(ctx context.Context, flow processnet.HostLoopbackFlow) (net.Conn, error) {
	store := d.context(ctx, flow)
	return d.connections.ConnWithProxy(store, netapi.ParseNetipAddrPort("tcp", flow.Mapping.Host), hostLoopbackProxy{d.direct, flow})
}

func (d hostLoopbackDialer) ListenUDP(ctx context.Context, flow processnet.HostLoopbackFlow) (net.PacketConn, error) {
	store := d.context(ctx, flow)
	return d.connections.PacketConnWithProxy(store, netapi.ParseNetipAddrPort("udp", flow.Mapping.Host), hostLoopbackProxy{d.direct, flow})
}

// hostLoopbackProxy is the "outbound" recorded for a forwarded flow: it can
// only reach the flow's own mapped loopback endpoint.
type hostLoopbackProxy struct {
	direct processnet.DirectHostLoopbackDialer
	flow   processnet.HostLoopbackFlow
}

var errHostLoopbackTarget = errors.New("host loopback forwarding: unexpected target")

func (p hostLoopbackProxy) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	if addr.String() != p.flow.Mapping.Host.String() {
		return nil, errHostLoopbackTarget
	}
	return p.direct.DialTCP(ctx, p.flow)
}

func (p hostLoopbackProxy) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	if addr.String() != p.flow.Mapping.Host.String() {
		return nil, errHostLoopbackTarget
	}
	return p.direct.ListenUDP(ctx, p.flow)
}

func (hostLoopbackProxy) Ping(context.Context, netapi.Address) (uint64, error) {
	return 0, errors.ErrUnsupported
}

func (hostLoopbackProxy) Dispatch(_ context.Context, a netapi.Address) (netapi.Address, error) {
	return a, nil
}

func (hostLoopbackProxy) Close() error { return nil }
