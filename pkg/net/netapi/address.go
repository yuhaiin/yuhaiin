package netapi

import (
	"net"
	"net/netip"
	"strconv"
	"unique"

	"github.com/Asutorufa/yuhaiin/pkg/log"
)

type Address interface {
	// Hostname return hostname of address, eg: www.example.com, 127.0.0.1, ff::ff
	Hostname() string
	// Port return port of address
	Port() uint16
	// IsFqdn return true if address is FQDN
	// fqdn must impl [DomainAddress]
	// otherwise must impl [IPAddress]
	IsFqdn() bool
	Equal(Address) bool
	net.Addr
}

type IPAddress interface {
	Address
	IP() net.IP
	WithZone(zone string)
}

type DomainAddress interface {
	Address
	UniqueHostname() unique.Handle[string]
}

func ParseAddress(network string, addr string) (ad Address, _ error) {
	hostname, portstr, err := net.SplitHostPort(addr)
	if err != nil {
		log.Error("split host port failed", "err", err, "addr", addr)
		hostname = addr
		portstr = "0"
	}

	pt, err := strconv.ParseUint(portstr, 10, 16)
	if err != nil {
		return nil, err
	}

	return ParseAddressPort(network, hostname, uint16(pt)), nil
}

func ParseDomainPort(network string, addr string, port uint16) (ad Address) {
	return &DomainAddr{
		hostname:       unique.Make(addr),
		port:           port,
		AddressNetwork: ParseAddressNetwork(network),
	}
}

func ParseAddressPort(network string, addr string, port uint16) (ad Address) {
	if addr, err := netip.ParseAddr(addr); err == nil {
		return &IPAddr{
			AddressNetwork: ParseAddressNetwork(network),
			Addr:           addr.Unmap(),
			port:           port,
		}
	}

	return ParseDomainPort(network, addr, port)
}

func ParseIPAddrPort(net string, ip net.IP, port uint16) Address {
	return &IPAddr{
		AddressNetwork: ParseAddressNetwork(net),
		Addr:           toAddrPort(ip, ""),
		port:           port,
	}
}

func toAddrPort(ad net.IP, zone string) netip.Addr {
	addr, _ := netip.AddrFromSlice(ad)
	addr = addr.Unmap()
	if zone != "" {
		addr = addr.WithZone(zone)
	}

	return addr
}

func ParseSysAddr(ad net.Addr) (Address, error) {
	switch ad := ad.(type) {
	case Address:
		return ad, nil
	case *net.TCPAddr:
		return &IPAddr{
			AddressNetwork: ParseAddressNetwork(ad.Network()),
			Addr:           toAddrPort(ad.IP, ad.Zone),
			port:           uint16(ad.Port),
		}, nil
	case *net.UDPAddr:
		return &IPAddr{
			AddressNetwork: ParseAddressNetwork(ad.Network()),
			Addr:           toAddrPort(ad.IP, ad.Zone),
			port:           uint16(ad.Port),
		}, nil
	case *net.IPAddr:
		return &IPAddr{
			AddressNetwork: ParseAddressNetwork(ad.Network()),
			Addr:           toAddrPort(ad.IP, ad.Zone),
			port:           0,
		}, nil
	case *net.UnixAddr:
		return &DomainAddr{
			hostname:       unique.Make(ad.Name),
			AddressNetwork: ParseAddressNetwork(ad.Network()),
		}, nil
	}
	return ParseAddress(ad.Network(), ad.String())
}

type AddressNetwork byte

const (
	Unknown AddressNetwork = iota
	TCP
	UDP
	IP
)

func ParseAddressNetwork(network string) AddressNetwork {
	switch network {
	case "tcp", "tcp4", "tcp6":
		return TCP
	case "udp", "udp4", "udp6":
		return UDP
	case "ip", "ip4", "ip6":
		return IP
	default:
		return Unknown
	}
}

func (n AddressNetwork) Network() string {
	switch n {
	case TCP:
		return "tcp"
	case UDP:
		return "udp"
	case IP:
		return "ip"
	default:
		return "unknown"
	}
}

var _ Address = (*DomainAddr)(nil)

type DomainAddr struct {
	hostname unique.Handle[string]
	AddressNetwork
	port uint16
}

func (d *DomainAddr) String() string {
	return net.JoinHostPort(d.hostname.Value(), strconv.Itoa(int(d.port)))
}
func (d *DomainAddr) Hostname() string { return d.hostname.Value() }
func (d *DomainAddr) Port() uint16     { return d.port }
func (d *DomainAddr) IsFqdn() bool     { return true }
func (d *DomainAddr) Equal(o Address) bool {
	x, ok := o.(*DomainAddr)
	if !ok {
		return false
	}
	return x.hostname == d.hostname && x.port == d.port
}
func (d *DomainAddr) UniqueHostname() unique.Handle[string] {
	return d.hostname
}

var _ IPAddress = (*IPAddr)(nil)

type IPAddr struct {
	Addr netip.Addr
	AddressNetwork
	port uint16
}

func (d *IPAddr) String() string       { return net.JoinHostPort(d.Addr.String(), strconv.Itoa(int(d.port))) }
func (d *IPAddr) Hostname() string     { return d.Addr.String() }
func (d *IPAddr) Port() uint16         { return d.port }
func (d *IPAddr) IsFqdn() bool         { return false }
func (d *IPAddr) IP() net.IP           { return d.Addr.AsSlice() }
func (d *IPAddr) WithZone(zone string) { d.Addr = d.Addr.WithZone(zone) }
func (d *IPAddr) Equal(o Address) bool {
	x, ok := o.(*IPAddr)
	if !ok {
		return false
	}

	return x.Addr.Compare(d.Addr) == 0 && x.port == d.port
}

var EmptyAddr Address = &DomainAddr{hostname: unique.Make("")}
