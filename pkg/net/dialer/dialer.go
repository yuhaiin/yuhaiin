package dialer

import (
	"context"
	"net"
	"syscall"
)

func ListenContext(ctx context.Context, network string, address string) (net.Listener, error) {
	return (&net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return setSocketOptions(network, address, c, &Options{
				InterfaceName:  DefaultInterfaceName,
				InterfaceIndex: DefaultInterfaceIndex,
				MarkSymbol:     DefaultMarkSymbol,
			})
		},
	}).
		Listen(ctx, network, address)
}

func DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return DialContextWithOptions(ctx, network, address, &Options{
		InterfaceName:  DefaultInterfaceName,
		InterfaceIndex: DefaultInterfaceIndex,
		MarkSymbol:     DefaultMarkSymbol,
	})
}

func DialContextWithOptions(ctx context.Context, network, address string, opts *Options) (net.Conn, error) {
	d := &net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			return setSocketOptions(network, address, c, opts)
		},
	}
	return d.DialContext(ctx, network, address)
}

func ListenPacket(network, address string) (net.PacketConn, error) {
	return ListenPacketWithOptions(network, address, &Options{
		InterfaceName:  DefaultInterfaceName,
		InterfaceIndex: DefaultInterfaceIndex,
		MarkSymbol:     DefaultMarkSymbol,
	})
}

func ListenPacketWithOptions(network, address string, opts *Options) (net.PacketConn, error) {
	lc := &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return setSocketOptions(network, address, c, opts)
		},
	}
	return lc.ListenPacket(context.Background(), network, address)
}

var (
	DefaultInterfaceName  = ""
	DefaultInterfaceIndex = 0
	DefaultRoutingMark    = 0 // maybe need root permission
	DefaultMarkSymbol     func(socket int32) bool
)

type Options struct {
	// InterfaceName is the name of interface/device to bind.
	// If a socket is bound to an interface, only packets received
	// from that particular interface are processed by the socket.
	InterfaceName string

	// InterfaceIndex is the index of interface/device to bind.
	// It is almost the same as InterfaceName except it uses the
	// index of the interface instead of the name.
	InterfaceIndex int

	// RoutingMark is the mark for each packet sent through this
	// socket. Changing the mark can be used for mark-based routing
	// without netfilter or for packet filtering.
	MarkSymbol func(socket int32) bool
}

func isTCPSocket(network string) bool {
	switch network {
	case "tcp", "tcp4", "tcp6":
		return true
	default:
		return false
	}
}

func isUDPSocket(network string) bool {
	switch network {
	case "udp", "udp4", "udp6":
		return true
	default:
		return false
	}
}
