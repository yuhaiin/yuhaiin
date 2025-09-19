package direct

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	probing "github.com/prometheus-community/pro-bing"
)

type direct struct {
	netapi.EmptyDispatch
	iface string
}

func init() {
	register.RegisterPoint(func(p *protocol.Direct, _ netapi.Proxy) (netapi.Proxy, error) {
		if p.GetNetworkInterface() != "" {
			return &direct{iface: p.GetNetworkInterface()}, nil
		}
		return Default, nil
	})

	register.SetBootstrap(Default)
}

func WithInterface(iface string) func(*direct) {
	return func(d *direct) {
		d.iface = iface
	}
}

var Default netapi.Proxy = NewDirect()

func NewDirect(f ...func(*direct)) netapi.Proxy {
	d := &direct{}
	for _, v := range f {
		v(d)
	}
	return d
}

func (d *direct) Conn(ctx context.Context, s netapi.Address) (net.Conn, error) {
	if d.iface != "" {
		ctx = context.WithValue(ctx, dialer.NetworkInterfaceKey{}, d.iface)
	}
	return dialer.DialHappyEyeballsv2(ctx, s)
}

func (d *direct) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	ur, err := dialer.ResolveUDPAddr(ctx, addr)
	if err != nil {
		return nil, err
	}

	p, err := dialer.ListenPacket(ctx, "udp", "", func(o *dialer.Options) {
		if d.iface != "" {
			o.InterfaceName = d.iface
		}

		o.PacketConnHintAddress = ur
	})
	if err != nil {
		return nil, fmt.Errorf("listen packet failed: %w", err)
	}

	return &UDPPacketConn{resolver: netapi.GetContext(ctx).Resolver, BufferPacketConn: NewBufferPacketConn(p)}, nil
}

func (d *direct) Ping(ctx context.Context, addr netapi.Address) (uint64, error) {
	var ip net.IP
	if addr.IsFqdn() {
		z, err := dialer.ResolverIP(ctx, addr)
		if err != nil {
			return 0, err
		}
		ip = z
	} else {
		ip = addr.(netapi.IPAddress).AddrPort().Addr().Unmap().AsSlice()
	}

	pinger := probing.New("")
	defer pinger.Stop()

	pinger.SetIPAddr(&net.IPAddr{IP: ip})
	var network string
	if ip.To4() == nil {
		network = "ip6"
	} else {
		network = "ip4"
	}

	iface, err := dialer.GetInterfaceByIP(ip)
	if err != nil {
		return 0, err
	}

	bindFd := func(uintptr) {}
	if iface != "" {
		bindFd = func(fd uintptr) {
			if err := dialer.BindInterface(network, fd, iface); err != nil {
				log.Warn("bind interface failed", "err", err)
			}
		}
	}

	pinger.SetNetwork(network)
	pinger.Control = func(fd uintptr) {
		bindFd(fd)

		if dialer.DefaultMarkSymbol != nil {
			if !dialer.DefaultMarkSymbol(int32(fd)) {
				log.Warn("mark symbol failed", "addr", addr)
			}
		}
	}

	pinger.SetPrivileged(false)
	pinger.Count = 1

	var resp uint64
	pinger.OnRecv = func(p *probing.Packet) {
		resp = uint64(p.Rtt)
	}

	pinger.OnDuplicateRecv = func(p *probing.Packet) {
		resp = uint64(p.Rtt)
	}

	err = pinger.RunWithContext(ctx) // Blocks until finished.
	if err != nil {
		return 0, fmt.Errorf("ping %v:%v failed: %w", addr, ip, err)
	}

	return resp, nil
}

func (d *direct) Close() error { return nil }

type BufferPacketConn interface {
	net.PacketConn
	SetReadBuffer(int) error
	SetWriteBuffer(int) error
}

func NewBufferPacketConn(p net.PacketConn) BufferPacketConn {
	x, ok := p.(BufferPacketConn)
	if ok {
		return x
	}
	return &bufferPacketConn{p}
}

type bufferPacketConn struct{ net.PacketConn }

func (p *bufferPacketConn) SetReadBuffer(int) error  { return nil }
func (p *bufferPacketConn) SetWriteBuffer(int) error { return nil }

type UDPPacketConn struct {
	resolver netapi.ContextResolver
	BufferPacketConn
}

func (p *UDPPacketConn) WriteTo(b []byte, addr net.Addr) (_ int, err error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		a, err := netapi.ParseSysAddr(addr)
		if err != nil {
			return 0, err
		}

		if a.IsFqdn() {
			store := netapi.WithContext(context.Background())
			store.Resolver = p.resolver
			ctx, cancel := context.WithTimeout(store, time.Second*5)
			udpAddr, err = dialer.ResolveUDPAddr(ctx, a)
			cancel()
		} else {
			udpAddr = net.UDPAddrFromAddrPort(a.(netapi.IPAddress).AddrPort())
		}
		if err != nil {
			return 0, err
		}
	}

	return p.BufferPacketConn.WriteTo(b, udpAddr)
}
