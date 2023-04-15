package dns

import (
	"context"
	"io"
	"net"

	"golang.org/x/net/dns/dnsmessage"
)

type DNS interface {
	LookupIP(ctx context.Context, domain string) ([]net.IP, error)
	Record(ctx context.Context, domain string, _ dnsmessage.Type) (_ []net.IP, ttl uint32, err error)
	Do(ctx context.Context, domain string, raw []byte) ([]byte, error)
	io.Closer
}

var _ DNS = (*ErrorDNS)(nil)

type ErrorDNS func(domain string) error

func (e ErrorDNS) LookupIP(_ context.Context, domain string) ([]net.IP, error) { return nil, e(domain) }
func (e ErrorDNS) Record(_ context.Context, domain string, _ dnsmessage.Type) ([]net.IP, uint32, error) {
	return nil, 0, e(domain)
}
func (e ErrorDNS) Do(context.Context, string, []byte) ([]byte, error) { return nil, e("") }
func (e ErrorDNS) Close() error                                       { return nil }
