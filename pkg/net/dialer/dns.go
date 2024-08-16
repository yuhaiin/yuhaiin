package dialer

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"golang.org/x/net/dns/dnsmessage"
)

var InternetResolver netapi.Resolver = NewSystemResolver("8.8.8.8:53", "1.1.1.1:53", "223.5.5.5:53", "114.114.114.114:53")

var Bootstrap netapi.Resolver = InternetResolver

type SystemResolver struct {
	resolver *net.Resolver
}

func NewSystemResolver(host ...string) *SystemResolver {
	return &SystemResolver{
		resolver: &net.Resolver{
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				for _, h := range host {
					conn, err := DialContext(ctx, network, h)
					if err == nil {
						return conn, nil
					}
				}
				return nil, fmt.Errorf("system dailer failed")
			},
		},
	}
}

func (d *SystemResolver) LookupIP(ctx context.Context, domain string, opts ...func(*netapi.LookupIPOption)) ([]net.IP, error) {
	opt := &netapi.LookupIPOption{}
	for _, o := range opts {
		o(opt)
	}

	network := "ip"

	switch opt.Mode {
	case netapi.ResolverModePreferIPv4:
		network = "ip4"
	case netapi.ResolverModePreferIPv6:
		network = "ip6"
	}

	return d.resolver.LookupIP(ctx, network, domain)
}

func (d *SystemResolver) Raw(context.Context, dnsmessage.Question) (dnsmessage.Message, error) {
	return dnsmessage.Message{}, fmt.Errorf("system dns not support")
}
func (d *SystemResolver) Close() error { return nil }

func ResolveUDPAddr(ctx context.Context, addr netapi.Address) (*net.UDPAddr, error) {
	ip, err := ResolverIP(ctx, addr)
	if err != nil {
		return nil, err
	}
	return &net.UDPAddr{IP: ip, Port: int(addr.Port())}, nil
}

func ResolveTCPAddr(ctx context.Context, addr netapi.Address) (*net.TCPAddr, error) {
	ip, err := ResolverIP(ctx, addr)
	if err != nil {
		return nil, err
	}
	return &net.TCPAddr{IP: ip, Port: int(addr.Port())}, nil
}

func ResolverAddrPort(ctx context.Context, addr netapi.Address) (netip.AddrPort, error) {
	if !addr.IsFqdn() {
		x, ok := addr.(*netapi.IPAddr)
		if ok {
			return netip.AddrPortFrom(x.Addr, x.Port()), nil
		}
	}

	ip, err := ResolverIP(ctx, addr)
	if err != nil {
		return netip.AddrPort{}, err
	}

	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("invalid ip %s", ip)
	}
	a = a.Unmap()
	return netip.AddrPortFrom(a, uint16(addr.Port())), nil
}

func ResolverIP(ctx context.Context, addr netapi.Address) (net.IP, error) {
	if !addr.IsFqdn() {
		return addr.(netapi.IPAddress).IP(), nil
	}

	ips, err := LookupIP(ctx, addr)
	if err != nil {
		return nil, err
	}
	return ips[rand.IntN(len(ips))], nil
}

func LookupIP(ctx context.Context, addr netapi.Address) ([]net.IP, error) {
	if !addr.IsFqdn() {
		return []net.IP{addr.(netapi.IPAddress).IP()}, nil
	}

	netctx := netapi.GetContext(ctx)

	resolver := Bootstrap
	if netctx.Resolver.ResolverSelf != nil {
		resolver = netctx.Resolver.ResolverSelf
	} else if netctx.Resolver.Resolver != nil {
		resolver = netctx.Resolver.Resolver
	}

	if netctx.Resolver.Mode != netapi.ResolverModeNoSpecified {
		ips, err := resolver.LookupIP(ctx, addr.Hostname(), netctx.Resolver.Opts(false)...)
		if err == nil {
			return ips, nil
		}
	}

	ips, err := resolver.LookupIP(ctx, addr.Hostname(), netctx.Resolver.Opts(true)...)
	if err != nil {
		return nil, fmt.Errorf("resolve address(%v) failed: %w", addr, err)
	}

	return ips, nil
}
