package node

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

// singleFamilyNodeProxy resolves destinations through the address family
// supported by the node, including protocols that otherwise resolve names remotely.
type singleFamilyNodeProxy struct {
	netapi.Proxy
	ipVersion contractnode.IPVersion
}

// ConnectionPoolIdentity refers to the stable parent proxy and family policy,
// rather than this short-lived request wrapper's address.
func (p *singleFamilyNodeProxy) ConnectionPoolIdentity() string {
	return fmt.Sprintf("%T:%p/family:%s", p.Proxy, p.Proxy, p.ipVersion)
}

var _ netapi.Proxy = (*singleFamilyNodeProxy)(nil)

func (p *singleFamilyNodeProxy) IPVersion() contractnode.IPVersion {
	return p.ipVersion
}

func (p *singleFamilyNodeProxy) Conn(ctx context.Context, address netapi.Address) (net.Conn, error) {
	addresses, err := p.addresses(ctx, address)
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
	return nil, fmt.Errorf("connect to %q through %s-only node: %w", address.Hostname(), p.ipVersion, lastErr)
}

func (p *singleFamilyNodeProxy) PacketConn(ctx context.Context, address netapi.Address) (net.PacketConn, error) {
	addresses, err := p.addresses(ctx, address)
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
	return nil, fmt.Errorf("open packet connection to %q through %s-only node: %w", address.Hostname(), p.ipVersion, lastErr)
}

func (p *singleFamilyNodeProxy) Ping(ctx context.Context, address netapi.Address) (uint64, error) {
	addresses, err := p.addresses(ctx, address)
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
	return 0, fmt.Errorf("ping %q through %s-only node: %w", address.Hostname(), p.ipVersion, lastErr)
}

func (p *singleFamilyNodeProxy) Dispatch(ctx context.Context, address netapi.Address) (netapi.Address, error) {
	if address == nil {
		return nil, errors.New("address is nil")
	}
	address = p.restoreDomain(ctx, address)
	dispatched, err := p.Proxy.Dispatch(ctx, address)
	if err != nil {
		return nil, err
	}
	addresses, err := p.addresses(ctx, dispatched)
	if err != nil {
		return nil, err
	}
	return addresses[0], nil
}

func (p *singleFamilyNodeProxy) addresses(ctx context.Context, address netapi.Address) ([]netapi.Address, error) {
	if address == nil {
		return nil, errors.New("address is nil")
	}
	address = p.restoreDomain(ctx, address)
	if ip, ok := address.(netapi.IPAddress); ok {
		if !p.supports(ip.AddrPort().Addr()) {
			return nil, p.unsupportedAddressError(address)
		}
		return []netapi.Address{ip}, nil
	}
	if !address.IsFqdn() {
		return nil, fmt.Errorf("unsupported address type %T", address)
	}

	resolver := netapi.GetContext(ctx).ConnOptions().Resolver().Resolver()
	if resolver == nil {
		resolver = netapi.Bootstrap()
	}
	mode, err := p.resolverMode()
	if err != nil {
		return nil, err
	}
	ips, err := resolver.LookupIP(ctx, address.Hostname(), func(option *netapi.LookupIPOption) {
		option.Mode = mode
	})
	if err != nil {
		return nil, fmt.Errorf("resolve %s address for %q: %w", p.ipVersion, address.Hostname(), err)
	}
	if ips == nil {
		return nil, fmt.Errorf("resolve %s address for %q: no addresses", p.ipVersion, address.Hostname())
	}

	var candidates []net.IP
	switch p.ipVersion {
	case contractnode.IPVersionIPv4:
		candidates = ips.A
	case contractnode.IPVersionIPv6:
		candidates = ips.AAAA
	default:
		return nil, fmt.Errorf("unsupported node IP version %q", p.ipVersion)
	}

	addresses := make([]netapi.Address, 0, len(candidates))
	for _, ip := range candidates {
		if !p.supportsIP(ip) {
			continue
		}
		addresses = append(addresses, netapi.ParseIPAddr(address.Network(), ip, address.Port()))
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("resolve %s address for %q: no addresses", p.ipVersion, address.Hostname())
	}
	return addresses, nil
}

func (p *singleFamilyNodeProxy) restoreDomain(ctx context.Context, address netapi.Address) netapi.Address {
	ip, ok := address.(netapi.IPAddress)
	if !ok || p.supports(ip.AddrPort().Addr()) {
		return address
	}

	netctx := netapi.GetContext(ctx)
	domain := netctx.GetDomainString()
	if domain == "" {
		return address
	}
	if originalIP := netctx.GetIPString(); originalIP != "" && originalIP != address.String() {
		return address
	}

	original, err := netapi.ParseAddress(address.Network(), domain)
	if err != nil || !original.IsFqdn() {
		return address
	}
	return original
}

func (p *singleFamilyNodeProxy) supports(addr netip.Addr) bool {
	switch p.ipVersion {
	case contractnode.IPVersionIPv4:
		return addr.Is4()
	case contractnode.IPVersionIPv6:
		return addr.Is6() && !addr.Is4In6()
	default:
		return false
	}
}

func (p *singleFamilyNodeProxy) supportsIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	return ok && p.supports(addr)
}

func (p *singleFamilyNodeProxy) resolverMode() (netapi.ResolverMode, error) {
	switch p.ipVersion {
	case contractnode.IPVersionIPv4:
		return netapi.ResolverModePreferIPv4, nil
	case contractnode.IPVersionIPv6:
		return netapi.ResolverModePreferIPv6, nil
	default:
		return netapi.ResolverModeNoSpecified, fmt.Errorf("unsupported node IP version %q", p.ipVersion)
	}
}

func (p *singleFamilyNodeProxy) unsupportedAddressError(address netapi.Address) error {
	switch p.ipVersion {
	case contractnode.IPVersionIPv4:
		return fmt.Errorf("IPv4-only node cannot reach non-IPv4 destination %q", address)
	case contractnode.IPVersionIPv6:
		return fmt.Errorf("IPv6-only node cannot reach non-IPv6 destination %q", address)
	default:
		return fmt.Errorf("unsupported node IP version %q", p.ipVersion)
	}
}
