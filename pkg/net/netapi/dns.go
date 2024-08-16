package netapi

import (
	"context"
	"io"
	"net"

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

var _ Resolver = (*ErrorResolver)(nil)

type ErrorResolver func(domain string) error

func (e ErrorResolver) LookupIP(_ context.Context, domain string, opts ...func(*LookupIPOption)) ([]net.IP, error) {
	return nil, e(domain)
}
func (e ErrorResolver) Close() error { return nil }
func (e ErrorResolver) Raw(_ context.Context, req dnsmessage.Question) (dnsmessage.Message, error) {
	return dnsmessage.Message{}, e(req.Name.String())
}
