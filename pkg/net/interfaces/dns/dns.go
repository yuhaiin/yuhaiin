package dns

import (
	"fmt"
	"io"
	"net"

	"golang.org/x/net/dns/dnsmessage"
)

type DNS interface {
	LookupIP(domain string) ([]net.IP, error)
	Record(domain string, _ dnsmessage.Type) (IPResponse, error)
	Do([]byte) ([]byte, error)
	// Resolver() *net.Resolver
	io.Closer
}

type IPResponse interface {
	IPs() []net.IP
	TTL() uint32
}

var _ IPResponse = (*ipResponse)(nil)

type ipResponse struct {
	ips []net.IP
	ttl uint32
}

func NewIPResponse(ips []net.IP, ttl uint32) IPResponse { return &ipResponse{ips, ttl} }
func (i ipResponse) IPs() []net.IP                      { return i.ips }
func (i ipResponse) TTL() uint32                        { return i.ttl }
func (i ipResponse) String() string                     { return fmt.Sprintf("{ips: %v, ttl: %d}", i.ips, i.ttl) }

var _ DNS = (*errorDNS)(nil)

type errorDNS struct{ error }

func NewErrorDNS(err error) DNS {
	return &errorDNS{err}
}
func (d *errorDNS) LookupIP(domain string) ([]net.IP, error) {
	return nil, fmt.Errorf("lookup %s failed: %w", domain, d.error)
}
func (d *errorDNS) Record(domain string, _ dnsmessage.Type) (IPResponse, error) { return nil, d.error }
func (d *errorDNS) Do([]byte) ([]byte, error)                                   { return nil, fmt.Errorf("do failed: %w", d.error) }
func (d *errorDNS) Close() error                                                { return nil }
