package direct

import (
	"context"
	"fmt"
	"net"
	"time"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/register"
)

type direct struct {
	netapi.EmptyDispatch
	iface string
}

func init() {
	register.RegisterContractPoint("direct", func(config contractnode.Direct, _ netapi.Proxy) (netapi.Proxy, error) {
		if iface := config.NetworkInterface; iface != "" {
			return &direct{iface: iface}, nil
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
		netapi.GetContext(ctx).ConnOptions().SetBindInterface(d.iface)
	}
	return dialer.DialHappyEyeballsv2(ctx, s)
}

func (d *direct) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	store := netapi.GetContext(ctx)

	bindAddr := store.ConnOptions().BindAddress()

	network := addr.Network()
	if network == "" {
		network = "udp"
	}

	p, err := dialer.ListenPacket(ctx, network, bindAddr,
		func(o *dialer.Options) {
			if d.iface != "" {
				o.InterfaceName = d.iface
			}

			// if bind address is not empty, we will use it
			// skip use hint address
			if bindAddr != "" || (addr.Hostname() == "" && addr.Port() == 0) {
				return
			}

			if !addr.IsFqdn() {
				o.PacketConnHintAddress = net.UDPAddrFromAddrPort(addr.(netapi.IPAddress).AddrPort())
				return
			}

			ur, err := netapi.ResolverIP(ctx, addr.Hostname())
			if err == nil {
				o.PacketConnHintAddress = ur.RandUDPAddr(addr.Port())
			}
		})
	if err != nil {
		return nil, fmt.Errorf("listen packet failed: %w", err)
	}

	return &UDPPacketConn{
		resolver:         store.ConnOptions().Resolver(),
		BufferPacketConn: NewBufferPacketConn(p),
	}, nil
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
	resolver *netapi.ResolverOptions
	BufferPacketConn
}

func (p *UDPPacketConn) WriteTo(b []byte, addr net.Addr) (_ int, err error) {
	return p.writeTo(context.Background(), b, addr)
}
func (p *UDPPacketConn) WriteToContext(ctx context.Context, b []byte, addr net.Addr) (int, error) {
	return p.writeTo(ctx, b, addr)
}
func (p *UDPPacketConn) writeTo(ctx context.Context, b []byte, addr net.Addr) (_ int, err error) {
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		a, err := netapi.ParseSysAddr(addr)
		if err != nil {
			return 0, err
		}

		if a.IsFqdn() {
			store := netapi.WithContext(ctx)
			store.ConnOptions().SetResolver(*p.resolver)
			ctx, cancel := context.WithTimeout(store, time.Second*5)
			ips, err := netapi.ResolverIP(ctx, a.Hostname())
			cancel()
			if err != nil {
				return 0, err
			}
			udpAddr = ips.RandUDPAddr(a.Port())
		} else {
			udpAddr = net.UDPAddrFromAddrPort(a.(netapi.IPAddress).AddrPort())
		}
	}

	return p.BufferPacketConn.WriteTo(b, udpAddr)
}
