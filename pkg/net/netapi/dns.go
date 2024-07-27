package netapi

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"golang.org/x/net/dns/dnsmessage"
)

type LookupIPOption struct {
	Mode ResolverMode
}

type Resolver interface {
	LookupIP(ctx context.Context, domain string, opts ...func(*LookupIPOption)) ([]net.IP, error)
	Raw(ctx context.Context, req dnsmessage.Question) (dnsmessage.Message, error)
	io.Closer
}

var InternetResolver Resolver = NewSystemResolver("8.8.8.8:53", "1.1.1.1:53", "223.5.5.5:53", "114.114.114.114:53")

var Bootstrap Resolver = InternetResolver

type SystemResolver struct {
	resolver *net.Resolver
}

func NewSystemResolver(host ...string) *SystemResolver {
	return &SystemResolver{
		resolver: &net.Resolver{
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				for _, h := range host {
					conn, err := dialer.DialContext(ctx, network, h)
					if err == nil {
						return conn, nil
					}
				}
				return nil, fmt.Errorf("system dailer failed")
			},
		},
	}
}

func (d *SystemResolver) LookupIP(ctx context.Context, domain string, opts ...func(*LookupIPOption)) ([]net.IP, error) {
	opt := &LookupIPOption{}
	for _, o := range opts {
		o(opt)
	}

	network := "ip"

	switch opt.Mode {
	case ResolverModePreferIPv4:
		network = "ip4"
	case ResolverModePreferIPv6:
		network = "ip6"
	}

	return d.resolver.LookupIP(ctx, network, domain)
}

func (d *SystemResolver) Raw(context.Context, dnsmessage.Question) (dnsmessage.Message, error) {
	return dnsmessage.Message{}, fmt.Errorf("system dns not support")
}
func (d *SystemResolver) Close() error { return nil }

var _ Resolver = (*ErrorResolver)(nil)

type ErrorResolver func(domain string) error

func (e ErrorResolver) LookupIP(_ context.Context, domain string, opts ...func(*LookupIPOption)) ([]net.IP, error) {
	return nil, e(domain)
}
func (e ErrorResolver) Close() error { return nil }
func (e ErrorResolver) Raw(_ context.Context, req dnsmessage.Question) (dnsmessage.Message, error) {
	return dnsmessage.Message{}, e(req.Name.String())
}
