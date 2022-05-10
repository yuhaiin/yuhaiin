package proxy

import (
	"fmt"
	"net"
	"strconv"
)

type Proxy interface {
	StreamProxy
	PacketProxy
}

type StreamProxy interface {
	Conn(host string) (net.Conn, error)
}

type PacketProxy interface {
	PacketConn(host string) (net.PacketConn, error)
}

type errProxy struct{ error }

func NewErrProxy(err error) Proxy                            { return &errProxy{err} }
func (e errProxy) Conn(string) (net.Conn, error)             { return nil, e.error }
func (e errProxy) PacketConn(string) (net.PacketConn, error) { return nil, e.error }

type Type string

const (
	DOMAIN Type = "DOMAIN"
	IP     Type = "IP"
)

type Address interface {
	// Host return Address, eg: www.example.com:443, 127.0.0.1:443, [ff::ff]:443
	Host() string
	// Hostname return hostname of address, eg: www.example.com, 127.0.0.1, ff::ff
	Hostname() string
	// IP return net.IP, if address is ip else return nil
	IP() net.IP
	// Port return port of address
	Port() uint16
	// Type return type of address, domain or ip
	Type() Type

	net.Addr
}

func ParseAddress(network, addr string) (ad Address, _ error) {
	hostname, ports, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("split host port failed: %w", err)
	}

	port, err := strconv.ParseUint(ports, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("parse port failed: %w", err)
	}

	ad = domain{addr, hostname, uint16(port), network}

	if i := net.ParseIP(hostname); i != nil {
		ad = ip{i, ad}
	}

	return
}

var _ Address = (*domain)(nil)

type domain struct {
	host string

	hostname string
	port     uint16

	network string
}

func (d domain) Host() string     { return d.host }
func (d domain) Hostname() string { return d.hostname }
func (d domain) IP() net.IP       { return nil }
func (d domain) Port() uint16     { return d.port }
func (d domain) Network() string  { return d.network }
func (d domain) String() string   { return d.Host() }
func (d domain) Type() Type       { return DOMAIN }

var _ Address = (*ip)(nil)

type ip struct {
	ip net.IP

	Address
}

func (i ip) IP() net.IP { return i.ip }
func (i ip) Type() Type { return IP }
