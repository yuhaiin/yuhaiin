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
	AAAA bool
	A    bool
}

type ForceFakeIP struct{}

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
	network := "ip"

	opt := &LookupIPOption{
		A: true,
	}

	for _, o := range opts {
		o(opt)
	}

	if opt.AAAA && !opt.A {
		network = "ip6"
	}

	if opt.A && !opt.AAAA {
		network = "ip4"
	}

	return d.resolver.LookupIP(ctx, network, domain)
}
func (d *SystemResolver) Raw(context.Context, dnsmessage.Question) (dnsmessage.Message, error) {
	return dnsmessage.Message{}, fmt.Errorf("system dns not support")
}
func (d *SystemResolver) Close() error { return nil }

type DNSErrCode struct {
	code dnsmessage.RCode
}

func NewDNSErrCode(code dnsmessage.RCode) *DNSErrCode {
	return &DNSErrCode{
		code: code,
	}
}

func (d *DNSErrCode) Code() dnsmessage.RCode {
	return d.code
}

func (d DNSErrCode) Error() string {
	return d.code.String()
}

func (d *DNSErrCode) As(err any) bool {
	dd, ok := err.(*DNSErrCode)
	if ok {
		dd.code = d.code
	}

	return ok
}

type DropResolver struct{}

func (e DropResolver) LookupIP(_ context.Context, domain string, opts ...func(*LookupIPOption)) ([]net.IP, error) {
	return nil, NewDNSErrCode(dnsmessage.RCodeSuccess)
}

func (e DropResolver) Close() error { return nil }
func (e DropResolver) Raw(_ context.Context, req dnsmessage.Question) (dnsmessage.Message, error) {
	return dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 0,
			Response:           true,
			Authoritative:      false,
			RecursionDesired:   false,
			RCode:              dnsmessage.RCodeSuccess,
			RecursionAvailable: false,
		},
		Questions: []dnsmessage.Question{
			{
				Name:  req.Name,
				Type:  req.Type,
				Class: dnsmessage.ClassINET,
			},
		},
	}, nil
}
