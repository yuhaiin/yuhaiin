package netapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
)

type ProcessDumper interface {
	ProcessName(network string, src, dst Address) (string, error)
}

type Proxy interface {
	StreamProxy
	PacketProxy
	Dispatch(context.Context, Address) (Address, error)
}

type StreamProxy interface {
	Conn(context.Context, Address) (net.Conn, error)
}

type PacketProxy interface {
	PacketConn(context.Context, Address) (net.PacketConn, error)
}

type Address interface {
	// Hostname return hostname of address, eg: www.example.com, 127.0.0.1, ff::ff
	Hostname() string
	// Port return port of address
	Port() uint16
	// IsFqdn return true if address is FQDN
	// not fqdn must impl [IPAddress]
	IsFqdn() bool
	net.Addr
}

type IPAddress interface {
	Address
	IP() net.IP
	WithZone(zone string)
}

func ResolveUDPAddr(ctx context.Context, addr Address) (*net.UDPAddr, error) {
	ip, err := ResolverIP(ctx, addr)
	if err != nil {
		return nil, err
	}
	return &net.UDPAddr{IP: ip, Port: int(addr.Port())}, nil
}

func ResolveTCPAddr(ctx context.Context, addr Address) (*net.TCPAddr, error) {
	ip, err := ResolverIP(ctx, addr)
	if err != nil {
		return nil, err
	}
	return &net.TCPAddr{IP: ip, Port: int(addr.Port())}, nil
}

func ResolverAddrPort(ctx context.Context, addr Address) (netip.AddrPort, error) {
	if !addr.IsFqdn() {
		x, ok := addr.(*IPAddr)
		if ok {
			return netip.AddrPortFrom(x.ip, x.port), nil
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

func ResolverIP(ctx context.Context, addr Address) (net.IP, error) {
	if !addr.IsFqdn() {
		return addr.(IPAddress).IP(), nil
	}

	ips, err := LookupIP(ctx, addr)
	if err != nil {
		return nil, err
	}
	return ips[rand.IntN(len(ips))], nil
}

func LookupIP(ctx context.Context, addr Address) ([]net.IP, error) {
	if !addr.IsFqdn() {
		return []net.IP{addr.(IPAddress).IP()}, nil
	}

	netctx := GetContext(ctx)

	resolver := Bootstrap
	if netctx.Resolver.ResolverSelf != nil {
		resolver = netctx.Resolver.ResolverSelf
	} else if netctx.Resolver.Resolver != nil {
		resolver = netctx.Resolver.Resolver
	}

	if netctx.Resolver.Mode != ResolverModeNoSpecified {
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

func IsBlockError(err error) bool {
	netErr := &net.OpError{}

	if errors.As(err, &netErr) {
		return netErr.Op == "block"
	}

	return false
}

func LogLevel(err error) slog.Level {
	if IsBlockError(err) {
		return slog.LevelDebug
	}

	return slog.LevelError
}
