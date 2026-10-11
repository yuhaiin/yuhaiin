package node

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

// ipv4OnlyNodeProxy resolves destinations to IPv4 before forwarding them,
// including for protocols that otherwise resolve destination names remotely.
type ipv4OnlyNodeProxy struct {
	netapi.Proxy
}

var _ netapi.Proxy = (*ipv4OnlyNodeProxy)(nil)

// IPv6Disabled reports that this node only accepts IPv4 destinations.
func (p *ipv4OnlyNodeProxy) IPv6Disabled() bool { return true }

func (p *ipv4OnlyNodeProxy) Conn(ctx context.Context, address netapi.Address) (net.Conn, error) {
	if err := validateIPv4OnlyAddress(address); err != nil {
		return nil, err
	}
	addresses, err := p.ipv4Addresses(ctx, address)
	if err != nil {
		return nil, err
	}

	var lastErr error
	for _, addr := range addresses {
		conn, err := p.Proxy.Conn(ctx, addr)
		if err == nil {
			return conn, nil
		}
		if conn != nil {
			_ = conn.Close()
		}
		lastErr = err
	}
	return nil, fmt.Errorf("connect to %q over IPv4: %w", address.Hostname(), lastErr)
}

func (p *ipv4OnlyNodeProxy) PacketConn(ctx context.Context, address netapi.Address) (net.PacketConn, error) {
	if err := validateIPv4OnlyAddress(address); err != nil {
		return nil, err
	}
	addresses, err := p.ipv4Addresses(ctx, address)
	if err != nil {
		return nil, err
	}

	var lastErr error
	for _, addr := range addresses {
		conn, err := p.Proxy.PacketConn(ctx, addr)
		if err == nil {
			return conn, nil
		}
		if conn != nil {
			_ = conn.Close()
		}
		lastErr = err
	}
	return nil, fmt.Errorf("open packet connection to %q over IPv4: %w", address.Hostname(), lastErr)
}

func (p *ipv4OnlyNodeProxy) Ping(ctx context.Context, address netapi.Address) (uint64, error) {
	if err := validateIPv4OnlyAddress(address); err != nil {
		return 0, err
	}
	addresses, err := p.ipv4Addresses(ctx, address)
	if err != nil {
		return 0, err
	}

	var lastErr error
	for _, addr := range addresses {
		latency, err := p.Proxy.Ping(ctx, addr)
		if err == nil {
			return latency, nil
		}
		lastErr = err
	}
	return 0, fmt.Errorf("ping %q over IPv4: %w", address.Hostname(), lastErr)
}

func (p *ipv4OnlyNodeProxy) Dispatch(ctx context.Context, address netapi.Address) (netapi.Address, error) {
	if err := validateIPv4OnlyAddress(address); err != nil {
		return nil, err
	}
	dispatched, err := p.Proxy.Dispatch(ctx, address)
	if err != nil {
		return nil, err
	}
	if dispatched == nil {
		return nil, errors.New("node returned an empty address")
	}
	if ip, ok := dispatched.(netapi.IPAddress); ok && ip.AddrPort().Addr().Is6() {
		return nil, errors.New("IPv6 is disabled for this node")
	}
	return dispatched, nil
}

func validateIPv4OnlyAddress(address netapi.Address) error {
	if address == nil {
		return errors.New("address is nil")
	}
	if ip, ok := address.(netapi.IPAddress); ok {
		if ip.AddrPort().Addr().Is6() {
			return errors.New("IPv6 is disabled for this node")
		}
		return nil
	}
	if !address.IsFqdn() {
		return fmt.Errorf("unsupported address type %T", address)
	}
	return nil
}

func (p *ipv4OnlyNodeProxy) ipv4Addresses(ctx context.Context, address netapi.Address) ([]netapi.Address, error) {
	if ip, ok := address.(netapi.IPAddress); ok {
		return []netapi.Address{ip}, nil
	}
	if !address.IsFqdn() {
		return nil, fmt.Errorf("unsupported address type %T", address)
	}

	resolver := netapi.GetContext(ctx).ConnOptions().Resolver().Resolver()
	if resolver == nil {
		resolver = netapi.Bootstrap()
	}
	ips, err := resolver.LookupIP(ctx, address.Hostname(), func(option *netapi.LookupIPOption) {
		option.Mode = netapi.ResolverModePreferIPv4
	})
	if err != nil {
		return nil, fmt.Errorf("resolve IPv4 address for %q: %w", address.Hostname(), err)
	}
	if ips == nil {
		return nil, fmt.Errorf("resolve IPv4 address for %q: no IPv4 addresses", address.Hostname())
	}
	addresses := make([]netapi.Address, 0, len(ips.A))
	for _, ip := range ips.A {
		if ip4 := ip.To4(); ip4 != nil {
			addresses = append(addresses, netapi.ParseIPAddr(address.Network(), ip4, address.Port()))
		}
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("resolve IPv4 address for %q: no IPv4 addresses", address.Hostname())
	}
	return addresses, nil
}
