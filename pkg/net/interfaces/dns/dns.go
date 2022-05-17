package dns

import (
	"io"
	"net"
)

type DNS interface {
	LookupIP(domain string) ([]net.IP, error)
	Do([]byte) ([]byte, error)
	// Resolver() *net.Resolver
	io.Closer
}

type Config struct {
	Name       string
	Host       string
	Servername string
	Subnet     *net.IPNet
}
