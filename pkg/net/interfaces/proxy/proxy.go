package proxy

import (
	"fmt"
	"log"
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

	ad = domainAddr{addr, hostname, port{uint16(por), ports}, network}

	var zone string
	if i := strings.LastIndexByte(hostname, '%'); i != -1 {
		zone = hostname[i+1:]
		hostname = hostname[:i]
	}

	if i := net.ParseIP(hostname); i != nil {
		ad = ipAddr{i, ad, zone}
	}

	return
}

func ParseAddressSplit(network, addr string, por uint16) (ad Address) {
	ports := strconv.FormatUint(uint64(por), 10)
	ad = domainAddr{net.JoinHostPort(addr, ports), addr, port{por, ports}, network}

	var zone string
	if i := strings.LastIndexByte(addr, '%'); i != -1 {
		zone = addr[i+1:]
		addr = addr[:i]
	}

	if i := net.ParseIP(addr); i != nil {
		ad = ipAddr{i, ad, zone}
	}

	return
}

func ParseTCPAddress(ad *net.TCPAddr) Address {
	return &ipAddr{
		Address: domainAddr{
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
	return &ipAddr{
		Address: domainAddr{
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
	return &ipAddr{
		Address: domainAddr{
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
	return domainAddr{
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

var _ Address = (*domainAddr)(nil)

type domainAddr struct {
	host string

	hostname string
	port     port

	network string
}

func (d domainAddr) String() string   { return d.host }
func (d domainAddr) Hostname() string { return d.hostname }
func (d domainAddr) IP() net.IP       { return nil }
func (d domainAddr) Port() Port       { return d.port }
func (d domainAddr) Network() string  { return d.network }
func (d domainAddr) Type() Type       { return DOMAIN }

var _ Address = (*ipAddr)(nil)

type ipAddr struct {
	origin net.IP
	Address
	zone string
}

func (i ipAddr) IP() net.IP   { return i.origin }
func (i ipAddr) Type() Type   { return IP }
func (i ipAddr) Zone() string { return i.zone }
func (i ipAddr) UDPAddr() *net.UDPAddr {
	return &net.UDPAddr{IP: i.origin, Port: int(i.Port().Port()), Zone: i.zone}
}
func (i ipAddr) TCPAddr() *net.TCPAddr {
	return &net.TCPAddr{IP: i.origin, Port: int(i.Port().Port()), Zone: i.zone}
}

var EmptyAddr = &emptyAddr{}

type emptyAddr struct{}

func (d emptyAddr) String() string   { return "" }
func (d emptyAddr) Hostname() string { return "" }
func (d emptyAddr) IP() net.IP       { return nil }
func (d emptyAddr) Port() Port       { return port{0, ""} }
func (d emptyAddr) Network() string  { return "" }
func (d emptyAddr) Type() Type       { return DOMAIN }

type port struct {
	n   uint16
	str string
}

func (p port) Port() uint16   { return p.n }
func (p port) String() string { return p.str }
