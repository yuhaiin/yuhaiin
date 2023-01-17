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

type errorDNS struct{ f func(domain string) error }

func NewErrorDNS(f func(domain string) error) DNS {
	return &errorDNS{f}
}
func (d *errorDNS) LookupIP(domain string) ([]net.IP, error) { return nil, d.f(domain) }
func (d *errorDNS) Record(domain string, _ dnsmessage.Type) (IPResponse, error) {
	return nil, d.f(domain)
}
func (d *errorDNS) Do([]byte) ([]byte, error) { return nil, d.f("") }
func (d *errorDNS) Close() error              { return nil }
