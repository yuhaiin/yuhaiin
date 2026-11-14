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
	"github.com/Asutorufa/yuhaiin/pkg/net/netstate"
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

// ListenContext opens an inbound listener. Listeners are protected (so replies
// to clients leave through the physical network, never our TUN) but are never
// bound to an egress interface.
func ListenContext(ctx context.Context, network string, address string) (net.Listener, error) {
	return ListenContextWithOptions(ctx, network, address, &Options{listener: true})
}

func ListenContextWithOptions(ctx context.Context, network string, address string, opts *Options) (net.Listener, error) {
	opts.listener = true
	config := &net.ListenConfig{
		KeepAliveConfig: KeepAliveConfig,
		Control: func(network, address string, c syscall.RawConn) error {
			return setSocketOptions(network, address, c, opts)
		},
	}

	return config.Listen(ctx, network, address)
}

func DialTCPContext(ctx context.Context, address netip.AddrPort, opts ...func(*Options)) (*TCPConn, error) {
	opt := &Options{}

	for _, o := range opts {
		o(opt)
	}

	return DialTCPContextWithOptions(ctx, address, opt)
}

// SkipInterface lists our own TUN interfaces. Sockets are never bound to
// them, and their presence means unprotected sockets could loop.
var SkipInterface = func() *set.Set[string] {
	return set.NewSet[string]()
}

// prepareEgress resolves the interface a new outbound socket is bound to
// (opts.InterfaceName, "" for none) and records it in the context.
func prepareEgress(ctx context.Context, opts *Options, dst netip.Addr) error {
	explicit := explicitInterface(netapi.GetContext(ctx).ConnOptions().BindInterface(), opts.InterfaceName)
	iface, err := resolveEgress(explicit, dst, protectorTrusted())
	if err != nil {
		return err
	}
	opts.InterfaceName = iface
	opts.egressDst = dst
	opts.explicit = explicit != ""
	opts.pathInterface = pathInterface(iface, dst)
	netapi.GetContext(ctx).SetInterface(opts.pathInterface)
	return nil
}

// pathInterface is the interface a socket's traffic actually uses, for
// network lifecycle tracking: the bound one, or for an unbound socket the one
// the OS routes its destination (or, without one, the default) through.
func pathInterface(bound string, dst netip.Addr) string {
	if bound != "" {
		return bound
	}
	if dst.IsValid() && dst.Unmap().IsGlobalUnicast() {
		if c, ok := selectRoute(dst.Unmap(), isOwnTun); ok {
			return c.Interface
		}
	}
	if name := defaultInterface(); !isOwnTun(name) {
		return name
	}
	return ""
}

func DialTCPContextWithOptions(ctx context.Context, address netip.AddrPort, opts *Options) (*TCPConn, error) {
	opts.networkID = ""
	var native *nativeBinding
	if address.Addr().IsGlobalUnicast() {
		native = newNativeBinding(ctx, addressFamily(address.Addr()))
	}
	defer native.close()
	if native != nil {
		ctx = native.ctx
	}
	if err := prepareEgress(ctx, opts, address.Addr()); err != nil {
		return nil, err
	}

	d := &net.Dialer{
		// Setting a negative value here prevents the Go stdlib from overriding
		// the values of TCP keepalive time and interval. It also prevents the
		// Go stdlib from enabling TCP keepalives by default.
		KeepAlive:       -1,
		KeepAliveConfig: KeepAliveConfig,
		LocalAddr:       opts.LocalAddr,
		Control: func(network, address string, c syscall.RawConn) error {
			if err := setSocketOptions(network, address, c, opts); err != nil {
				return err
			}
			return native.control(c, opts)
		},
	}

	d.SetMultipathTCP(false)

	before := dialPath(netstate.Default, opts.pathInterface, localIP(opts.LocalAddr), address.Addr())
	if native != nil {
		before = netstate.Path{}
	}
	ctx, release := pendingDial(ctx, netstate.Default, before)
	defer release()
	raw, err := d.DialTCP(ctx, "tcp", netip.AddrPort{}, address)
	if err != nil {
		return nil, dialError(ctx, err)
	}
	if native != nil {
		before = native.path
	}
	return trackTCP(netstate.Default, raw, before, opts.networkID)
}

func WithListener() func(*Options) {
	return func(opts *Options) {
		opts.listener = true
	}
}

func ListenPacket(ctx context.Context, network, address string, opts ...func(*Options)) (net.PacketConn, error) {
	opt := &Options{}

	for _, o := range opts {
		o(opt)
	}

	return ListenPacketWithOptions(ctx, network, address, opt)
}

const socketBufferSize = 7 << 20

func ListenPacketWithOptions(ctx context.Context, network, address string, opts *Options) (net.PacketConn, error) {
	opts.networkID = ""
	var native *nativeBinding
	defer func() { native.close() }()

	lc := &net.ListenConfig{
		// Setting a negative value here prevents the Go stdlib from overriding
		// the values of TCP keepalive time and interval.
		KeepAlive:       -1,
		KeepAliveConfig: KeepAliveConfig,
		Control: func(network, address string, c syscall.RawConn) error {
			if err := setSocketOptions(network, address, c, opts); err != nil {
				return err
			}
			return native.control(c, opts)
		},
	}

	lc.SetMultipathTCP(false)

	if !opts.listener {
		// A listen-style outbound socket may send anywhere; its egress is
		// chosen from the destination hint, or the default route without one.
		var dst netip.Addr
		if opts.PacketConnHintAddress != nil {
			dst = localIP(opts.PacketConnHintAddress)
		}
		if err := prepareEgress(ctx, opts, dst); err != nil {
			return nil, err
		}
	}

	var family uint8
	if opts.PacketConnHintAddress != nil {
		family = addressFamily(localIP(opts.PacketConnHintAddress))
	}
	switch network {
	case "udp4":
		family = 4
	case "udp6":
		family = 6
	}
	before := netstate.Default.Capture(opts.pathInterface, netip.Addr{}, family)
	bindNative := !opts.listener
	if hint := opts.PacketConnHintAddress; hint != nil && !localIP(hint).IsGlobalUnicast() {
		// A socket for loopback or link-local peers belongs to no network:
		// a change of the default network must not invalidate it.
		bindNative = false
		before = netstate.Path{}
		opts.untracked = true
	}
	if host, _, err := net.SplitHostPort(address); err == nil {
		if ip, err := netip.ParseAddr(host); err == nil && !ip.IsUnspecified() && !ip.IsGlobalUnicast() {
			bindNative = false
			before = netstate.Path{}
		}
	}
	if bindNative {
		native = newNativeBinding(ctx, family)
		if native != nil {
			ctx = native.ctx
		}
	}
	pc, err := lc.ListenPacket(ctx, network, address)
	if err != nil {
		return nil, err
	}
	if native != nil {
		before = native.path
	}

	// copy from https://github.com/tailscale/tailscale/blob/cf739256caa86d8ba48f107bb22c623de0d0822d/net/udprelay/server.go#L459C1-L459C33
	if up, ok := pc.(*net.UDPConn); ok {
		_ = up.SetWriteBuffer(socketBufferSize)
		_ = up.SetReadBuffer(socketBufferSize)
		if !opts.listener {
			return trackUDP(netstate.Default, up, opts, before, family)
		}
	}

	// if opts.tryUpgradeToBatch && runtime.GOOS == "linux" {
	// 	uc, ok := pc.(*net.UDPConn)
	// 	if ok {
	// 		pc = NewBatchPacketConn(uc)
	// 	}
	// }

	return pc, nil
}

type Options struct {
	networkID string // actual native binding, populated only by Control
	// OnNetworkInvalidated replaces automatic UDP socket closure for owners
	// with native roaming support. It must only signal bounded owner work,
	// and must capture/check the old socket rather than close a mutable slot.
	OnNetworkInvalidated func()
	LocalAddr            net.Addr

	// PacketConnHintAddress is the first destination of a listen-style UDP
	// socket; Egress Selection picks its interface from it.
	PacketConnHintAddress *net.UDPAddr

	// InterfaceName pins the socket to this interface ("use exactly this
	// one"). Left empty, Egress Selection decides; after preparation it
	// holds the chosen interface, or "" when the socket stays unbound.
	InterfaceName string

	// egressDst is the destination the egress was chosen for, and explicit
	// whether InterfaceName came from the caller or configuration.
	egressDst netip.Addr
	explicit  bool
	// pathInterface is the interface tracked for network changes (the
	// bound one, or the routed one for unbound sockets); untracked sockets
	// talk to scoped peers and follow no network path.
	pathInterface string
	untracked     bool

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

func GetDefaultInterfaceAddress(v6 bool) (net.IP, error) {
	var iface *net.Interface
	name := ConfiguredInterface()
	if name == "" {
		name = interfaces.DefaultInterfaceName()
	}
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
