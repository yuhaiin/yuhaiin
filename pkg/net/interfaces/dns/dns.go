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

var _ DNS = (*errorDNS)(nil)

type errorDNS struct{ f func(domain string) error }

func NewErrorDNS(f func(domain string) error) DNS { return &errorDNS{f} }
func (d *errorDNS) LookupIP(ctx context.Context, domain string) ([]net.IP, error) {
	return nil, d.f(domain)
}
func (d *errorDNS) Record(ctx context.Context, domain string, _ dnsmessage.Type) (IPRecord, error) {
	return IPRecord{}, d.f(domain)
}
func (d *errorDNS) Do(context.Context, string, []byte) ([]byte, error) { return nil, d.f("") }
func (d *errorDNS) Close() error                                       { return nil }
