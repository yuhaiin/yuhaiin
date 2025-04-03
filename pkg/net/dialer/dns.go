package dialer

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"golang.org/x/net/dns/dnsmessage"
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

func (b *bootstrapResolver) LookupIP(ctx context.Context, domain string, opts ...func(*netapi.LookupIPOption)) ([]net.IP, error) {
	b.mu.RLock()
	r := b.r
	b.mu.RUnlock()

	if r == nil {
		return nil, errors.New("bootstrap resolver is nil")
	}

	return r.LookupIP(ctx, domain, opts...)
}

func (b *bootstrapResolver) Raw(ctx context.Context, req dnsmessage.Question) (dnsmessage.Message, error) {
	b.mu.RLock()
	r := b.r
	b.mu.RUnlock()

	if r == nil {
		return dnsmessage.Message{}, errors.New("bootstrap resolver is nil")
	}

	return r.Raw(ctx, req)
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
		x, ok := addr.(netapi.IPAddr)
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

	resolver := Bootstrap()
	if netctx.Resolver.ResolverResolver() != nil {
		resolver = netctx.Resolver.ResolverResolver()
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
