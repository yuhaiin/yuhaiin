package dialer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/Asutorufa/yuhaiin/pkg/net/netstate"
)

// TCPConn retains net.TCPConn's optional interfaces (half-close, syscall,
// splice/read-from and socket options) while unregistering on owner close.
type TCPConn struct {
	*net.TCPConn
	path         netstate.Path
	registration *netstate.Registration
	once         sync.Once
	closeErr     error
	invalid      atomic.Bool
}

func (c *TCPConn) NetworkPath() netstate.Path { return c.path }

func (c *TCPConn) Read(b []byte) (int, error) {
	n, err := c.TCPConn.Read(b)
	if err != nil && c.invalid.Load() {
		err = errors.Join(err, netstate.ErrInvalidated)
	}
	return n, err
}

func (c *TCPConn) Close() error {
	c.once.Do(func() {
		_ = c.registration.Close()
		c.closeErr = c.TCPConn.Close()
	})
	return c.closeErr
}

// UDPConn preserves OOB/batching/buffer/syscall capabilities used by QUIC.
// No lifecycle lookup or lock is introduced on ReadFrom/WriteTo.
type UDPConn struct {
	*net.UDPConn
	path         netstate.Path
	registration *netstate.Registration
	once         sync.Once
	closeErr     error
	invalid      atomic.Bool
	closed       atomic.Bool
	recovery     atomic.Pointer[func()]
}

func (c *UDPConn) NetworkPath() netstate.Path { return c.path }

// SetNetworkRecovery transfers invalidation to an owner with native socket
// migration. The handler must only signal its existing worker. Installing it
// after an already delivered invalidation also signals recovery; duplicate
// signals are possible, so the owner checks the exact old socket.
func (c *UDPConn) SetNetworkRecovery(handler func()) {
	if handler == nil {
		return
	}
	c.recovery.Store(new(handler))
	if c.invalid.Load() && !c.closed.Load() {
		handler()
	}
}

func (c *UDPConn) Closed() bool { return c.closed.Load() }

func (c *UDPConn) NetworkInvalidated() bool { return c.invalid.Load() }

func (c *UDPConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.UDPConn.ReadFrom(b)
	if err != nil && c.invalid.Load() {
		err = errors.Join(err, netstate.ErrInvalidated)
	}
	return n, addr, err
}

func (c *UDPConn) Close() error {
	c.once.Do(func() {
		c.closed.Store(true)
		_ = c.registration.Close()
		c.closeErr = c.UDPConn.Close()
	})
	return c.closeErr
}

func localIP(addr net.Addr) netip.Addr {
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.AddrPort().Addr().WithZone("").Unmap()
	case *net.UDPAddr:
		return a.AddrPort().Addr().WithZone("").Unmap()
	default:
		return netip.Addr{}
	}
}

func addressFamily(ip netip.Addr) uint8 {
	if !ip.IsValid() || ip.IsUnspecified() {
		return 0
	}
	if ip.Is4() {
		return 4
	}
	return 6
}

func pendingDial(ctx context.Context, m *netstate.Manager, p netstate.Path) (context.Context, func()) {
	if !p.Known() {
		return ctx, func() {}
	}
	dialCtx, cancel := context.WithCancelCause(ctx)
	r := m.Register(p, func(netstate.Event) { cancel(netstate.ErrInvalidated) })
	return dialCtx, func() { _ = r.Close(); cancel(context.Canceled) }
}

func dialPath(m *netstate.Manager, iface string, local, remote netip.Addr) netstate.Path {
	if !remote.IsGlobalUnicast() {
		// Platform Control deliberately skips interface binding for loopback
		// and link-local destinations. A default-route hint is not affinity.
		iface = ""
		if !local.IsValid() || local.IsUnspecified() {
			return netstate.Path{}
		}
	}
	return m.Capture(iface, local, addressFamily(remote))
}

func trackTCP(m *netstate.Manager, raw *net.TCPConn, before netstate.Path, networkID string) (*TCPConn, error) {
	// Capture actual binding before validating the attempt's token. This order
	// closes the race where an A -> B -> A transition finishes during connect.
	p := m.Capture("", localIP(raw.LocalAddr()), addressFamily(localIP(raw.LocalAddr())))
	if networkID != "" {
		p = m.CaptureNetwork(networkID, localIP(raw.LocalAddr()), addressFamily(localIP(raw.LocalAddr())))
	}
	if !m.Valid(before) {
		_ = raw.Close()
		return nil, netstate.ErrInvalidated
	}
	c := &TCPConn{TCPConn: raw, path: p}
	c.registration = m.Register(p, func(netstate.Event) { c.invalid.Store(true); _ = raw.Close() })
	return c, nil
}

func trackUDP(m *netstate.Manager, raw *net.UDPConn, opts *Options, before netstate.Path, family uint8) (*UDPConn, error) {
	p := m.Capture(opts.InterfaceName, localIP(raw.LocalAddr()), family)
	if opts.networkID != "" {
		p = m.CaptureNetwork(opts.networkID, localIP(raw.LocalAddr()), family)
	}
	if !m.Valid(before) {
		_ = raw.Close()
		return nil, netstate.ErrInvalidated
	}
	c := &UDPConn{UDPConn: raw, path: p}
	onInvalidated := opts.OnNetworkInvalidated
	if onInvalidated != nil {
		c.recovery.Store(new(onInvalidated))
	}
	c.registration = m.Register(p, func(netstate.Event) {
		c.invalid.Store(true)
		if handler := c.recovery.Load(); handler != nil {
			(*handler)()
		} else {
			_ = raw.Close()
		}
	})
	return c, nil
}

func dialError(ctx context.Context, err error) error {
	if errors.Is(context.Cause(ctx), netstate.ErrInvalidated) {
		return errors.Join(err, netstate.ErrInvalidated)
	}
	return err
}

// DialUDPContext opens a connected UDP socket for a native transport owner
// such as IKEv2. It applies the same protection/interface options as ordinary
// outbounds. The owner tracks the established socket so native roaming can
// swap it without automatic closure racing the protocol exchange.
func DialUDPContext(ctx context.Context, remote netip.AddrPort) (*net.UDPConn, error) {
	c, _, err := DialUDPContextWithPath(ctx, remote)
	return c, err
}

// DialUDPContextWithPath also hands the creation token to the native owner,
// closing the gap between a completed connect syscall and owner registration.
func DialUDPContextWithPath(ctx context.Context, remote netip.AddrPort) (*net.UDPConn, netstate.Path, error) {
	iface, err := getInterface(remote)
	if err != nil {
		return nil, netstate.Path{}, err
	}
	opt := &Options{InterfaceName: iface, MarkSymbol: DefaultMarkSymbol}
	var native *nativeBinding
	if remote.Addr().IsGlobalUnicast() {
		native = newNativeBinding(ctx, addressFamily(remote.Addr()))
	}
	defer native.close()
	if native != nil {
		ctx = native.ctx
	}
	p := dialPath(netstate.Default, iface, netip.Addr{}, remote.Addr())
	if native != nil {
		p = netstate.Path{}
	}
	ctx, release := pendingDial(ctx, netstate.Default, p)
	defer release()
	d := &net.Dialer{Control: func(network, address string, c syscall.RawConn) error {
		if err := setSocketOptions(network, address, c, opt); err != nil {
			return err
		}
		return native.control(c, opt)
	}}
	c, err := d.DialUDP(ctx, "udp", netip.AddrPort{}, remote)
	if err != nil {
		return nil, netstate.Path{}, dialError(ctx, err)
	}
	actual := netstate.Default.Capture("", localIP(c.LocalAddr()), addressFamily(localIP(c.LocalAddr())))
	if native != nil {
		p = native.path
		if opt.networkID != "" {
			actual = netstate.Default.CaptureNetwork(opt.networkID, localIP(c.LocalAddr()), addressFamily(localIP(c.LocalAddr())))
		}
	}
	if !netstate.Default.Valid(p) {
		_ = c.Close()
		return nil, netstate.Path{}, netstate.ErrInvalidated
	}
	return c, actual, nil
}
