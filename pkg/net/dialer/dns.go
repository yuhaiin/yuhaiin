package dialer

import (
	"context"
	"errors"
	"fmt"
	"net"
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

func ResolverIP(ctx context.Context, addr string) (*netapi.IPs, error) {
	netctx := netapi.GetContext(ctx).ConnOptions().Resolver()

	resolver := netctx.Resolver()
	if resolver == nil {
		resolver = Bootstrap()
	}

	if netctx.Mode() != netapi.ResolverModeNoSpecified {
		ips, err := resolver.LookupIP(ctx, addr, netctx.Opts(false)...)
		if err == nil {
			return ips, nil
		}
	}

	ips, err := resolver.LookupIP(ctx, addr, netctx.Opts(true)...)
	if err != nil {
		return nil, fmt.Errorf("resolve address(%v) failed: %w", addr, err)
	}

	return ips, nil
}
