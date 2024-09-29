package dialer

import (
	"context"
	"net"
	"syscall"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
)

// UDP socket read/write buffer size (7MB). The value of 7MB is chosen as it is
// the max supported by a default configuration of macOS. Some platforms will
// silently clamp the value to other maximums, such as linux clamping to
// net.core.{r,w}mem_max (see _linux.go for additional implementation that works
// around this limitation)
const SocketBufferSize = 7 << 20

var KeepAliveConfig = net.KeepAliveConfig{
	Enable:   true,
	Idle:     time.Second * 300,
	Interval: time.Second * 20,
	Count:    9,
}

func ListenContext(ctx context.Context, network string, address string) (net.Listener, error) {
	return ListenContextWithOptions(ctx, network, address, &Options{
		InterfaceName:  DefaultInterfaceName,
		InterfaceIndex: DefaultInterfaceIndex,
		MarkSymbol:     DefaultMarkSymbol,
	})
}

func ListenContextWithOptions(ctx context.Context, network string, address string, opts *Options) (net.Listener, error) {
	opts.listener = true

	config := &net.ListenConfig{
		KeepAliveConfig: KeepAliveConfig,
		Control: func(network, address string, c syscall.RawConn) error {
			return setSocketOptions(network, address, c, opts)
		},
	}
	if configuration.MPTCP {
		config.SetMultipathTCP(true)
	}
	return config.Listen(ctx, network, address)
}

func DialContext(ctx context.Context, network, address string, opts ...func(*Options)) (net.Conn, error) {
	opt := &Options{
		InterfaceName:  DefaultInterfaceName,
		InterfaceIndex: DefaultInterfaceIndex,
		MarkSymbol:     DefaultMarkSymbol,
	}

	for _, o := range opts {
		o(opt)
	}

	return DialContextWithOptions(ctx, network, address, opt)
}

func DialContextWithOptions(ctx context.Context, network, address string, opts *Options) (net.Conn, error) {
	d := &net.Dialer{
		// Setting a negative value here prevents the Go stdlib from overriding
		// the values of TCP keepalive time and interval. It also prevents the
		// Go stdlib from enabling TCP keepalives by default.
		KeepAlive:       -1,
		KeepAliveConfig: KeepAliveConfig,
		// This method is called after the underlying network socket is created,
		// but before dialing the socket (or calling its connect() method). The
		// combination of unconditionally enabling TCP keepalives here, and
		// disabling the overriding of TCP keepalive parameters by setting the
		// KeepAlive field to a negative value above, results in OS defaults for
		// the TCP keealive interval and time parameters.
		LocalAddr: opts.LocalAddr,
		Control: func(network, address string, c syscall.RawConn) error {
			return setSocketOptions(network, address, c, opts)
		},
	}

	if configuration.MPTCP {
		d.SetMultipathTCP(true)
	}
	return d.DialContext(ctx, network, address)
}

func WithListener() func(*Options) {
	return func(opts *Options) {
		opts.listener = true
	}
}

func WithTryUpgradeToBatch() func(*Options) {
	return func(opts *Options) {
		opts.tryUpgradeToBatch = true
	}
}

func ListenPacket(network, address string, opts ...func(*Options)) (net.PacketConn, error) {
	opt := &Options{
		InterfaceName:  DefaultInterfaceName,
		InterfaceIndex: DefaultInterfaceIndex,
		MarkSymbol:     DefaultMarkSymbol,
	}

	for _, o := range opts {
		o(opt)
	}

	return ListenPacketWithOptions(network, address, opt)
}

func ListenPacketWithOptions(network, address string, opts *Options) (net.PacketConn, error) {
	lc := &net.ListenConfig{
		// Setting a negative value here prevents the Go stdlib from overriding
		// the values of TCP keepalive time and interval. It also prevents the
		// Go stdlib from enabling TCP keepalives by default.
		KeepAlive:       -1,
		KeepAliveConfig: KeepAliveConfig,
		// This method is called after the underlying network socket is created,
		// but before dialing the socket (or calling its connect() method). The
		// combination of unconditionally enabling TCP keepalives here, and
		// disabling the overriding of TCP keepalive parameters by setting the
		// KeepAlive field to a negative value above, results in OS defaults for
		// the TCP keealive interval and time parameters.
		Control: func(network, address string, c syscall.RawConn) error {
			return setSocketOptions(network, address, c, opts)
		},
	}
	pc, err := lc.ListenPacket(context.Background(), network, address)
	if err != nil {
		return nil, err
	}

	// if opts.tryUpgradeToBatch && runtime.GOOS == "linux" {
	// 	uc, ok := pc.(*net.UDPConn)
	// 	if ok {
	// 		pc = NewBatchPacketConn(uc)
	// 	}
	// }

	return pc, nil
}

var (
	DefaultInterfaceName  = ""
	DefaultInterfaceIndex = 0
	DefaultRoutingMark    = 0 // maybe need root permission
	DefaultMarkSymbol     func(socket int32) bool
)

type Options struct {

	// RoutingMark is the mark for each packet sent through this
	// socket. Changing the mark can be used for mark-based routing
	// without netfilter or for packet filtering.
	MarkSymbol func(socket int32) bool

	// InterfaceName is the name of interface/device to bind.
	// If a socket is bound to an interface, only packets received
	// from that particular interface are processed by the socket.
	InterfaceName string

	// InterfaceIndex is the index of interface/device to bind.
	// It is almost the same as InterfaceName except it uses the
	// index of the interface instead of the name.
	InterfaceIndex int

	LocalAddr net.Addr

	listener          bool
	tryUpgradeToBatch bool
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
