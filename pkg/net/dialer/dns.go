package dialer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/miekg/dns"
)

var bootstrap = &bootstrapResolver{}

func init() {
	net.DefaultResolver = &net.Resolver{
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return netapi.NewDnsConn(context.TODO(), Bootstrap()), nil
		},
	}
}

type bootstrapResolver struct {
	r  netapi.Resolver
	mu sync.RWMutex
}

func (b *bootstrapResolver) LookupIP(ctx context.Context, domain string, opts ...func(*netapi.LookupIPOption)) (*netapi.IPs, error) {
	b.mu.RLock()
	r := b.r
	b.mu.RUnlock()

	if r == nil {
		return nil, errors.New("bootstrap resolver is not initialized")
	}

	return r.LookupIP(ctx, domain, opts...)
}

func (b *bootstrapResolver) Raw(ctx context.Context, req dns.Question) (dns.Msg, error) {
	b.mu.RLock()
	r := b.r
	b.mu.RUnlock()

	if r == nil {
		return dns.Msg{}, errors.New("bootstrap resolver is not initialized")
	}

	return r.Raw(ctx, req)
}

func (b *bootstrapResolver) Name() string {
	b.mu.RLock()
	r := b.r
	b.mu.RUnlock()
	if r == nil {
		return "bootstrap"
	}

	name := r.Name()
	if strings.ToLower(name) == "bootstrap" {
		return name
	}

	return fmt.Sprintf("bootstrap(%s)", name)
}

func (b *bootstrapResolver) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	var err error
	if b.r != nil {
		err = b.r.Close()
		b.r = nil
	}

	return err
}

func (b *bootstrapResolver) SetBootstrap(r netapi.Resolver) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.r != nil {
		if err := b.r.Close(); err != nil {
			log.Warn("close bootstrap resolver failed", "err", err)
		}
	}

	b.r = r
}

func Bootstrap() netapi.Resolver     { return bootstrap }
func SetBootstrap(r netapi.Resolver) { bootstrap.SetBootstrap(r) }

func ResolveUDPAddr(ctx context.Context, addr netapi.Address) (*net.UDPAddr, error) {
	if !addr.IsFqdn() {
		return net.UDPAddrFromAddrPort(addr.(netapi.IPAddress).AddrPort()), nil
	}

	ip, err := ResolverIP(ctx, addr)
	if err != nil {
		return nil, err
	}
	return &net.UDPAddr{IP: ip, Port: int(addr.Port())}, nil
}

func ResolveTCPAddr(ctx context.Context, addr netapi.Address) (*net.TCPAddr, error) {
	if !addr.IsFqdn() {
		return net.TCPAddrFromAddrPort(addr.(netapi.IPAddress).AddrPort()), nil
	}

	ip, err := ResolverIP(ctx, addr)
	if err != nil {
		return nil, err
	}
	return &net.TCPAddr{IP: ip, Port: int(addr.Port())}, nil
}

func ResolverAddrPort(ctx context.Context, addr netapi.Address) (netip.AddrPort, error) {
	if !addr.IsFqdn() {
		x, ok := addr.(netapi.IPAddress)
		if ok {
			return x.AddrPort(), nil
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
		return addr.(netapi.IPAddress).AddrPort().Addr().AsSlice(), nil
	}

	ips, err := lookupIP(ctx, addr)
	if err != nil {
		return nil, err
	}
	return ips.Rand(), nil
}

func lookupIP(ctx context.Context, addr netapi.Address) (*netapi.IPs, error) {
	if !addr.IsFqdn() {
		ip := addr.(netapi.IPAddress).AddrPort().Addr()
		if ip.Is4() {
			return &netapi.IPs{A: []net.IP{ip.AsSlice()}}, nil
		}

		return &netapi.IPs{AAAA: []net.IP{ip.AsSlice()}}, nil
	}

	netctx := netapi.GetContext(ctx)

	resolver := netctx.ConnOptions().Resolver().Resolver()
	if resolver == nil {
		resolver = Bootstrap()
	}

	if netctx.ConnOptions().Resolver().Mode() != netapi.ResolverModeNoSpecified {
		ips, err := resolver.LookupIP(ctx, addr.Hostname(), netctx.ConnOptions().Resolver().Opts(false)...)
		if err == nil {
			return ips, nil
		}
	}

	ips, err := resolver.LookupIP(ctx, addr.Hostname(), netctx.ConnOptions().Resolver().Opts(true)...)
	if err != nil {
		return nil, fmt.Errorf("resolve address(%v) failed: %w", addr, err)
	}

	return ips, nil
}
