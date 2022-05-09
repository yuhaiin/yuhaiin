package dns

import (
	"io"
	"net"
)

type DNS interface {
	LookupIP(domain string) ([]net.IP, error)
	// Resolver() *net.Resolver
	io.Closer
}
