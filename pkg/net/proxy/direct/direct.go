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

type PacketConnNoWarpKey struct{}

var Default netapi.Proxy = NewDirect()

func NewDirect() netapi.Proxy {
	return &direct{}
}

func (d *direct) Conn(ctx context.Context, s netapi.Address) (net.Conn, error) {
	if d.iface != "" {
		ctx = context.WithValue(ctx, dialer.NetworkInterfaceKey{}, d.iface)
	}
	return dialer.DialHappyEyeballsv2(ctx, s)
}

func (d *direct) PacketConn(ctx context.Context, _ netapi.Address) (net.PacketConn, error) {
	opts := []func(*dialer.Options){
		dialer.WithTryUpgradeToBatch(),
	}

	if d.iface != "" {
		ctx = context.WithValue(ctx, dialer.NetworkInterfaceKey{}, d.iface)
	}

	p, err := dialer.ListenPacket(ctx, "udp", "", opts...)
	if err != nil {
		return nil, fmt.Errorf("listen packet failed: %w", err)
	}

	if ctx.Value(PacketConnNoWarpKey{}) == true {
		return p, nil
	}

	return &UDPPacketConn{resolver: netapi.GetContext(ctx).Resolver, BufferPacketConn: NewBufferPacketConn(p)}, nil
}

func (d *direct) Ping(ctx context.Context, addr netapi.Address) (uint64, error) {
	var ip string
	var v6 bool
	var localhost bool
	if addr.IsFqdn() {
		z, err := dialer.ResolverIP(ctx, addr)
		if err != nil {
			return 0, err
		}
		v6 = z.To4() == nil
		if !v6 {
			z = z.To4()
		}
		ip = z.String()
		localhost = z.IsLoopback()
	} else {
		z := addr.(netapi.IPAddress).AddrPort().Addr()
		v6 = !z.Unmap().Is4()
		ip = z.Unmap().String()
		localhost = z.Unmap().IsLoopback()
	}

	pinger, err := probing.NewPinger(ip)
	if err != nil {
		return 0, fmt.Errorf("ping %v:%v failed: %w", addr, ip, err)
	}

	if !localhost {
		saddr, err := dialer.GetDefaultInterfaceAddress(v6)
		if err == nil {
			pinger.Source = saddr.String()
		} else {
			log.Error("get default interface address failed", "err", err)
		}
	}

	pinger.SetPrivileged(false)
	defer pinger.Stop()

	pinger.Count = 1
	err = pinger.RunWithContext(ctx) // Blocks until finished.
	if err != nil {
		return 0, fmt.Errorf("ping %v:%v failed: %w", addr, ip, err)
	}

	return uint64(pinger.Statistics().MinRtt.Milliseconds()), nil
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
