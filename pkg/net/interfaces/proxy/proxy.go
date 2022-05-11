package proxy

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"strconv"
	"strings"
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
	IP() net.IP
	// Port return port of address
	Port() Port
	// Type return type of address, domain or ip
	Type() Type

	net.Addr
}

type IPAddress interface {
	Address

	Zone() string // IPv6 scoped addressing zone
	UDPAddr() *net.UDPAddr
	TCPAddr() *net.TCPAddr
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

	ad = DomainAddr{addr, hostname, port{uint16(por), ports}, network}

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
	ad = DomainAddr{net.JoinHostPort(addr, ports), addr, port{por, ports}, network}

	var zone string
	if i := strings.LastIndexByte(addr, '%'); i != -1 {
		zone = addr[i+1:]
		addr = addr[:i]
	}

	if i := net.ParseIP(addr); i != nil {
		ad = IPAddr{i, ad, zone}
	}

	return
}

func ParseTCPAddress(ad *net.TCPAddr) Address {
	return IPAddr{
		Address: DomainAddr{
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
	return IPAddr{
		Address: DomainAddr{
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
	return IPAddr{
		Address: DomainAddr{
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
	return DomainAddr{
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

func ResolveIPAddress(addr Address, lookup func(string) ([]net.IP, error)) (IPAddress, error) {
	if addr == nil {
		return nil, fmt.Errorf("addr is nil")
	}

	if a, ok := addr.(IPAddress); ok {
		return a, nil
	}

	if lookup == nil {
		return nil, fmt.Errorf("lookup func is nil")
	}

	ips, err := lookup(addr.Hostname())
	if err != nil {
		return nil, fmt.Errorf("resolve address failed: %w", err)
	}

	ip := ips[rand.Intn(len(ips))]

	if z, ok := addr.(DomainAddr); ok {
		z.hostname = ip.String()
		z.host = net.JoinHostPort(z.hostname, z.port.String())
		addr = z
	}

	return IPAddr{ip, addr, ""}, nil
}

var _ Address = (*DomainAddr)(nil)

type DomainAddr struct {
	host string

	hostname string
	port     port

	network string
}

func (d DomainAddr) String() string   { return d.host }
func (d DomainAddr) Hostname() string { return d.hostname }
func (d DomainAddr) IP() net.IP       { return nil }
func (d DomainAddr) Port() Port       { return d.port }
func (d DomainAddr) Network() string  { return d.network }
func (d DomainAddr) Type() Type       { return DOMAIN }

var _ IPAddress = (*IPAddr)(nil)

type IPAddr struct {
	origin net.IP
	Address
	zone string
}

func (i IPAddr) IP() net.IP   { return i.origin }
func (i IPAddr) Type() Type   { return IP }
func (i IPAddr) Zone() string { return i.zone }
func (i IPAddr) UDPAddr() *net.UDPAddr {
	return &net.UDPAddr{IP: i.origin, Port: int(i.Port().Port()), Zone: i.zone}
}
func (i IPAddr) TCPAddr() *net.TCPAddr {
	return &net.TCPAddr{IP: i.origin, Port: int(i.Port().Port()), Zone: i.zone}
}

var EmptyAddr = &emptyAddr{}

type emptyAddr struct{}

func (d emptyAddr) String() string   { return "" }
func (d emptyAddr) Hostname() string { return "" }
func (d emptyAddr) IP() net.IP       { return nil }
func (d emptyAddr) Port() Port       { return port{0, ""} }
func (d emptyAddr) Network() string  { return "" }
func (d emptyAddr) Type() Type       { return EMPTY }

type port struct {
	n   uint16
	str string
}

func (p port) Port() uint16   { return p.n }
func (p port) String() string { return p.str }
