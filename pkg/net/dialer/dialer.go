package dialer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer/interfaces"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/set"
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
	Interval: time.Second * 15,
	Count:    9,
}

func ListenContext(ctx context.Context, network string, address string) (net.Listener, error) {
	return ListenContextWithOptions(ctx, network, address, &Options{
		InterfaceName: DefaultInterfaceName(),
		MarkSymbol:    DefaultMarkSymbol,
		listener:      true,
	})
}

func ListenContextWithOptions(ctx context.Context, network string, address string, opts *Options) (net.Listener, error) {
	config := &net.ListenConfig{
		KeepAliveConfig: KeepAliveConfig,
		Control: func(network, address string, c syscall.RawConn) error {
			return setSocketOptions(network, address, c, opts)
		},
	}

	return config.Listen(ctx, network, address)
}

func DialContext(ctx context.Context, network, address string, opts ...func(*Options)) (net.Conn, error) {
	opt := &Options{
		InterfaceName: DefaultInterfaceName(),
		MarkSymbol:    DefaultMarkSymbol,
	}

	for _, o := range opts {
		o(opt)
	}

	return DialContextWithOptions(ctx, network, address, opt)
}

var SkipInterface = func() *set.Set[string] {
	return set.NewSet[string]()
}

func DialContextWithOptions(ctx context.Context, network, address string, opts *Options) (net.Conn, error) {
	iface := netapi.GetContext(ctx).ConnOptions().BindInterface()
	if iface != "" {
		opts.InterfaceName = iface
	}

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

	store := netapi.GetContext(ctx)

	if opts.InterfaceName != "" {
		if SkipInterface().Has(opts.InterfaceName) {
			return nil, fmt.Errorf("block dial to skip infinite loop: iface: %s, addr: %s", iface, address)
		}

		store.SetInterface(opts.InterfaceName)
	} else {
		iface, err := getInterface(address)
		if err != nil {
			return nil, err
		}

		opts.InterfaceName = iface
		store.SetInterface(iface)
	}

	return d.DialContext(ctx, network, address)
}

func getInterface(address string) (string, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return "", nil
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return "", nil
	}

	return GetInterfaceByIP(ip)
}

func GetInterfaceByIP(ip net.IP) (string, error) {
	iface, ok := interfaces.DefaultRouter().SearchIP(ip)
	if ok && !SkipInterface().Has(iface) {
		return iface, nil
	}

	iface = interfaces.DefaultInterfaceName()
	if SkipInterface().Has(iface) {
		return "", fmt.Errorf("block dial to skip infinite loop: iface: %s, addr: %v", iface, ip)
	}

	return iface, nil
}

func WithListener() func(*Options) {
	return func(opts *Options) {
		opts.listener = true
	}
}

func withTryUpgradeToBatch() func(*Options) {
	return func(opts *Options) {
		opts.tryUpgradeToBatch = true
	}
}

func ListenPacket(ctx context.Context, network, address string, opts ...func(*Options)) (net.PacketConn, error) {
	opt := &Options{
		InterfaceName: DefaultInterfaceName(),
		MarkSymbol:    DefaultMarkSymbol,
	}

	for _, o := range opts {
		o(opt)
	}

	return ListenPacketWithOptions(ctx, network, address, opt)
}

const socketBufferSize = 7 << 20

func ListenPacketWithOptions(ctx context.Context, network, address string, opts *Options) (net.PacketConn, error) {
	iface := netapi.GetContext(ctx).ConnOptions().BindInterface()
	if iface != "" {
		opts.InterfaceName = iface
	}

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

	store := netapi.GetContext(ctx)

	if opts.InterfaceName != "" {
		if SkipInterface().Has(opts.InterfaceName) {
			return nil, fmt.Errorf("block dial to skip infinite loop: iface: %s, addr: %s", iface, opts.PacketConnHintAddress)
		}

		store.SetInterface(opts.InterfaceName)
	} else if opts.PacketConnHintAddress != nil {
		iface, err := GetInterfaceByIP(opts.PacketConnHintAddress.IP)
		if err != nil {
			return nil, err
		}

		opts.InterfaceName = iface
		store.SetInterface(iface)
	} else {
		iface = interfaces.DefaultInterfaceName()
		if SkipInterface().Has(iface) {
			return nil, fmt.Errorf("block dial to skip infinite loop: iface: %s, addr: %v", iface, opts.PacketConnHintAddress)
		}

		opts.InterfaceName = iface
		store.SetInterface(iface)
	}

	pc, err := lc.ListenPacket(ctx, network, address)
	if err != nil {
		return nil, err
	}

	// copy from https://github.com/tailscale/tailscale/blob/cf739256caa86d8ba48f107bb22c623de0d0822d/net/udprelay/server.go#L459C1-L459C33
	if up, ok := pc.(*net.UDPConn); ok {
		_ = up.SetWriteBuffer(socketBufferSize)
		_ = up.SetReadBuffer(socketBufferSize)
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
	DefaultInterfaceName = func() string { return "" }
	DefaultRoutingMark   = 0 // maybe need root permission
	DefaultMarkSymbol    func(socket int32) bool
)

type Options struct {
	LocalAddr net.Addr

	// RoutingMark is the mark for each packet sent through this
	// socket. Changing the mark can be used for mark-based routing
	// without netfilter or for packet filtering.
	MarkSymbol func(socket int32) bool

	// PacketConnHintAddress to detect default interface
	PacketConnHintAddress *net.UDPAddr

	// InterfaceName is the name of interface/device to bind.
	// If a socket is bound to an interface, only packets received
	// from that particular interface are processed by the socket.
	InterfaceName string

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

func isLocalhost(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// error means the string didn't contain a port number, so use the string directly
		host = addr
	}

	// localhost6 == RedHat /etc/hosts for ::1, ip6-loopback & ip6-localhost == Debian /etc/hosts for ::1
	if host == "localhost" || host == "localhost6" || host == "ip6-loopback" || host == "ip6-localhost" {
		return true
	}

	ip, _ := netip.ParseAddr(host)
	return ip.IsLoopback()
}

func GetDefaultInterfaceAddress(v6 bool) (net.IP, error) {
	var iface *net.Interface
	name := DefaultInterfaceName()
	if name != "" {
		var err error
		iface, err = net.InterfaceByName(name)
		if err != nil {
			log.Warn("get default interface failed", "err", err)
		}
	}

	if iface == nil {
		return nil, errors.New("default interface not found")
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("get default interface address failed: %w", err)
	}

	var remainv6 net.IP
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}

		iv4 := ipnet.IP.To4() != nil

		if !iv4 && v6 {
			if ipnet.IP.IsGlobalUnicast() {
				return ipnet.IP, nil
			}
			remainv6 = ipnet.IP
		} else if iv4 && !v6 {
			return ipnet.IP.To4(), nil
		}
	}

	if remainv6 != nil {
		return remainv6, nil
	}

	return nil, errors.New("default interface not found")
}
