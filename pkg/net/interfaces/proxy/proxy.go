package proxy

import (
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strconv"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils/resolver"
)

type Proxy interface {
	StreamProxy
	PacketProxy
}

type StreamProxy interface {
	Conn(Address) (net.Conn, error)
}

type PacketProxy interface {
	PacketConn(Address) (net.PacketConn, error)
}

type errProxy struct{ error }

func NewErrProxy(err error) Proxy                             { return &errProxy{err} }
func (e errProxy) Conn(Address) (net.Conn, error)             { return nil, e.error }
func (e errProxy) PacketConn(Address) (net.PacketConn, error) { return nil, e.error }

type Type string

const (
	DOMAIN Type = "DOMAIN"
	IP     Type = "IP"
	UNIX   Type = "UNIX"
	EMPTY  Type = "EMPTY"
)

type Port interface {
	Port() uint16
	String() string
}

type Address interface {
	// Hostname return hostname of address, eg: www.example.com, 127.0.0.1, ff::ff
	Hostname() string
	// IP return net.IP, if address is ip else return nil
	IP() (net.IP, error)
	// Port return port of address
	Port() Port
	// Type return type of address, domain or ip
	Type() Type

	net.Addr

	WithResolver(dns.DNS)

	Zone() string // IPv6 scoped addressing zone
	UDPAddr() (*net.UDPAddr, error)
	TCPAddr() (*net.TCPAddr, error)
	// IPHost if address is ip, return host, else resolve domain to ip and return JoinHostPort(ip,port)
	IPHost() (string, error)
}

func ParseAddress(network, addr string) (ad Address, _ error) {
	hostname, ports, err := net.SplitHostPort(addr)
	if err != nil {
		log.Printf("split host port failed: %v\n", err)
		hostname = addr
		ports = "0"
	}

	por, err := strconv.ParseUint(ports, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("parse port failed: %w", err)
	}

	ad = &DomainAddr{
		host:     addr,
		hostname: hostname,
		port:     port{uint16(por), ports},
		network:  network,
	}

	var zone string
	if i := strings.LastIndexByte(hostname, '%'); i != -1 {
		zone = hostname[i+1:]
		hostname = hostname[:i]
	}

	if i := net.ParseIP(hostname); i != nil {
		ad = IPAddr{i, ad, zone}
	}

	return
}

func ParseAddressSplit(network, addr string, por uint16) (ad Address) {
	ports := strconv.FormatUint(uint64(por), 10)
	ad = &DomainAddr{
		host:     net.JoinHostPort(addr, ports),
		hostname: addr,
		port:     port{por, ports},
		network:  network,
	}

	var zone string
	if i := strings.LastIndexByte(addr, '%'); i != -1 {
		zone = addr[i+1:]
		addr = addr[:i]
	}

	if i := net.ParseIP(addr); i != nil {
		ad = &IPAddr{i, ad, zone}
	}

	return
}

func ParseTCPAddress(ad *net.TCPAddr) Address {
	return &IPAddr{
		Address: &DomainAddr{
			host:     ad.String(),
			hostname: ad.IP.String(),
			port:     port{uint16(ad.Port), strconv.Itoa(ad.Port)},
			network:  ad.Network(),
		},
		origin: ad.IP,
		zone:   ad.Zone,
	}
}

func ParseUDPAddr(ad *net.UDPAddr) Address {
	return &IPAddr{
		Address: &DomainAddr{
			host:     ad.String(),
			hostname: ad.IP.String(),
			port:     port{uint16(ad.Port), strconv.Itoa(ad.Port)},
			network:  ad.Network(),
		},
		origin: ad.IP,
		zone:   ad.Zone,
	}
}

func ParseIPAddr(ad *net.IPAddr) Address {
	return &IPAddr{
		Address: &DomainAddr{
			host:     net.JoinHostPort(ad.String(), "0"),
			hostname: ad.IP.String(),
			port:     port{0, "0"},
			network:  ad.Network(),
		},
		origin: ad.IP,
		zone:   ad.Zone,
	}
}

func ParseUnixAddr(ad *net.UnixAddr) Address {
	return &DomainAddr{
		host:     net.JoinHostPort(ad.String(), "0"),
		hostname: ad.Name,
		port:     port{0, "0"},
		network:  ad.Network(),
	}
}

func ParseSysAddr(ad net.Addr) (Address, error) {
	switch ad := ad.(type) {
	case *net.TCPAddr:
		return ParseTCPAddress(ad), nil
	case *net.UDPAddr:
		return ParseUDPAddr(ad), nil
	case *net.IPAddr:
		return ParseIPAddr(ad), nil
	case *net.UnixAddr:
		return ParseUnixAddr(ad), nil
	}

	return ParseAddress(ad.Network(), ad.String())
}

var _ Address = (*DomainAddr)(nil)

type DomainAddr struct {
	host string

	hostname string
	port     port

	network string

	resolver dns.DNS
}

func (d DomainAddr) String() string   { return d.host }
func (d DomainAddr) Hostname() string { return d.hostname }
func (d DomainAddr) IP() (net.IP, error) {
	ip, err := d.lookupIP()
	if err != nil {
		return nil, fmt.Errorf("resolve address %s failed: %w", d.hostname, err)
	}

	return ip, nil
}
func (d DomainAddr) Port() Port                     { return d.port }
func (d DomainAddr) Network() string                { return d.network }
func (d DomainAddr) Type() Type                     { return DOMAIN }
func (d *DomainAddr) WithResolver(resolver dns.DNS) { d.resolver = resolver }
func (d DomainAddr) Zone() string                   { return "" }
func (d DomainAddr) lookupIP() (net.IP, error) {
	lookup := d.resolver
	if lookup == nil {
		lookup = resolver.Bootstrap
	}

	ips, err := lookup.LookupIP(d.hostname)
	if err != nil {
		return nil, fmt.Errorf("resolve address failed: %w", err)
	}

	return ips[rand.Intn(len(ips))], nil
}

func (d DomainAddr) UDPAddr() (*net.UDPAddr, error) {
	ip, err := d.lookupIP()
	if err != nil {
		return nil, fmt.Errorf("resolve udp address %s failed: %w", d.hostname, err)
	}

	return &net.UDPAddr{IP: ip, Port: int(d.port.Port())}, nil
}

func (d DomainAddr) TCPAddr() (*net.TCPAddr, error) {
	ip, err := d.lookupIP()
	if err != nil {
		return nil, fmt.Errorf("resolve tcp address %s failed: %w", d.hostname, err)
	}

	return &net.TCPAddr{IP: ip, Port: int(d.port.Port())}, nil
}
func (d DomainAddr) IPHost() (string, error) {
	ip, err := d.IP()
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(ip.String(), d.port.String()), nil
}

var _ Address = (*IPAddr)(nil)

type IPAddr struct {
	origin net.IP
	Address
	zone string
}

func (i IPAddr) IP() (net.IP, error) { return i.origin, nil }
func (i IPAddr) Type() Type          { return IP }
func (i IPAddr) Zone() string        { return i.zone }
func (i IPAddr) UDPAddr() (*net.UDPAddr, error) {
	return &net.UDPAddr{IP: i.origin, Port: int(i.Port().Port()), Zone: i.zone}, nil
}
func (i IPAddr) TCPAddr() (*net.TCPAddr, error) {
	return &net.TCPAddr{IP: i.origin, Port: int(i.Port().Port()), Zone: i.zone}, nil
}
func (i IPAddr) IPHost() (string, error) { return i.String(), nil }

var EmptyAddr = &emptyAddr{}

type emptyAddr struct{}

func (d emptyAddr) String() string                 { return "" }
func (d emptyAddr) Hostname() string               { return "" }
func (d emptyAddr) IP() (net.IP, error)            { return nil, errors.New("empty") }
func (d emptyAddr) Port() Port                     { return port{0, ""} }
func (d emptyAddr) Network() string                { return "" }
func (d emptyAddr) Type() Type                     { return EMPTY }
func (d emptyAddr) WithResolver(dns.DNS)           {}
func (d emptyAddr) Zone() string                   { return "" }
func (d emptyAddr) UDPAddr() (*net.UDPAddr, error) { return nil, errors.New("empty") }
func (d emptyAddr) TCPAddr() (*net.TCPAddr, error) { return nil, errors.New("empty") }
func (d emptyAddr) IPHost() (string, error)        { return "", errors.New("empty") }

type port struct {
	n   uint16
	str string
}

func (p port) Port() uint16   { return p.n }
func (p port) String() string { return p.str }
