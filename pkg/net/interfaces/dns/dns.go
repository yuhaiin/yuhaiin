package dns

import (
	"context"
	"fmt"
	"io"
	"net"

	"golang.org/x/net/dns/dnsmessage"
)

type DNS interface {
	LookupIP(ctx context.Context, domain string) ([]net.IP, error)
	Record(ctx context.Context, domain string, _ dnsmessage.Type) (IPRecord, error)
	Do(ctx context.Context, domain string, raw []byte) ([]byte, error)
	io.Closer
}

type IPRecord struct {
	IPs []net.IP
	TTL uint32
}

func (i IPRecord) String() string { return fmt.Sprintf("{ips: %v, ttl: %d}", i.IPs, i.TTL) }

var _ DNS = (*ErrorDNS)(nil)

type ErrorDNS func(domain string) error

func (e ErrorDNS) LookupIP(ctx context.Context, domain string) ([]net.IP, error) {
	return nil, e(domain)
}
func (e ErrorDNS) Record(ctx context.Context, domain string, _ dnsmessage.Type) (IPRecord, error) {
	return IPRecord{}, e(domain)
}
func (e ErrorDNS) Do(context.Context, string, []byte) ([]byte, error) { return nil, e("") }
func (e ErrorDNS) Close() error                                       { return nil }
