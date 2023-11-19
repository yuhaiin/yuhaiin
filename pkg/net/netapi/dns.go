package netapi

import (
	"context"
	"fmt"
	"io"
	"net"

	"golang.org/x/net/dns/dnsmessage"
)

type ForceFakeIP struct{}

type Resolver interface {
	LookupIP(ctx context.Context, domain string) ([]net.IP, error)
	Record(ctx context.Context, domain string, _ dnsmessage.Type) (_ []net.IP, ttl uint32, err error)
	Do(ctx context.Context, domain string, raw []byte) ([]byte, error)
	io.Closer
}

var _ Resolver = (*ErrorResolver)(nil)

type ErrorResolver func(domain string) error

func (e ErrorResolver) LookupIP(_ context.Context, domain string) ([]net.IP, error) {
	return nil, e(domain)
}
func (e ErrorResolver) Record(_ context.Context, domain string, _ dnsmessage.Type) ([]net.IP, uint32, error) {
	return nil, 0, e(domain)
}
func (e ErrorResolver) Do(context.Context, string, []byte) ([]byte, error) { return nil, e("") }
func (e ErrorResolver) Close() error                                       { return nil }

var Bootstrap Resolver = &System{}

type System struct{ DisableIPv6 bool }

func (d *System) LookupIP(ctx context.Context, domain string) ([]net.IP, error) {
	var network string
	if d.DisableIPv6 {
		network = "ip4"
	} else {
		network = "ip"
	}
	return net.DefaultResolver.LookupIP(ctx, network, domain)
}

func (d *System) Record(ctx context.Context, domain string, t dnsmessage.Type) ([]net.IP, uint32, error) {
	var req string
	if t == dnsmessage.TypeAAAA {
		req = "ip6"
	} else {
		req = "ip4"
	}

	ips, err := net.DefaultResolver.LookupIP(ctx, req, domain)
	if err != nil {
		return nil, 0, err
	}

	return ips, 60, nil
}

func (d *System) Close() error { return nil }
func (d *System) Do(context.Context, string, []byte) ([]byte, error) {
	return nil, fmt.Errorf("system dns not support")
}
