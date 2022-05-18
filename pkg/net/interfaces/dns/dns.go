package dns

import (
	"fmt"
	"io"
	"net"
)

type DNS interface {
	LookupIP(domain string) ([]net.IP, error)
	Do([]byte) ([]byte, error)
	// Resolver() *net.Resolver
	io.Closer
}

var _ DNS = (*errorDNS)(nil)

type errorDNS struct{ error }

func NewErrorDNS(err error) DNS {
	return &errorDNS{err}
}
func (d *errorDNS) LookupIP(domain string) ([]net.IP, error) {
	return nil, fmt.Errorf("lookup %s failed: %w", domain, d.error)
}
func (d *errorDNS) Do([]byte) ([]byte, error) { return nil, fmt.Errorf("do failed: %w", d.error) }
func (d *errorDNS) Close() error              { return nil }

type Config struct {
	Name       string
	Host       string
	Servername string
	Subnet     *net.IPNet
}
