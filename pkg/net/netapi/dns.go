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
	Raw(ctx context.Context, req dnsmessage.Question) (dnsmessage.Message, error)
	io.Closer
}

var _ Resolver = (*ErrorResolver)(nil)

type ErrorResolver func(domain string) error

func (e ErrorResolver) LookupIP(_ context.Context, domain string) ([]net.IP, error) {
	return nil, e(domain)
}
func (e ErrorResolver) Close() error { return nil }
func (e ErrorResolver) Raw(_ context.Context, req dnsmessage.Question) (dnsmessage.Message, error) {
	return dnsmessage.Message{}, e(req.Name.String())
}

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
func (d *System) Raw(context.Context, dnsmessage.Question) (dnsmessage.Message, error) {
	return dnsmessage.Message{}, fmt.Errorf("system dns not support")
}
func (d *System) Close() error { return nil }

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

	dd.code = d.code

	return ok
}

type DropResolver struct{}

func (e DropResolver) LookupIP(_ context.Context, domain string) ([]net.IP, error) {
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
