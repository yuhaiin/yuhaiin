package netapi

import (
	"errors"
	"hash/maphash"
	"net"
	"net/netip"
	"strconv"
	"unique"
)

var seed = maphash.MakeSeed()

// ComputeAddressHash compute hash of address
func ComputeAddressHash[t comparable](tt t) uint64 { return maphash.Comparable(seed, tt) }

type Address interface {
	// Hostname return hostname of address, eg: www.example.com, 127.0.0.1, ff::ff
	Hostname() string
	// Port return port of address
	Port() uint16
	// IsFqdn return true if address is FQDN
	// fqdn must impl [DomainAddress]
	// otherwise must impl [IPAddress]
	IsFqdn() bool
	// Comparable return hash of address, compute by [ComputeAddressHash]
	Comparable() uint64
	net.Addr
}

type IPAddress interface {
	Address
	IP() net.IP
}

type DomainAddress interface {
	Address
	UniqueHostname() unique.Handle[string]
}

func ParseAddress(network string, addr string) (ad Address, _ error) {
	var port uint64
	hostname, portstr, err := net.SplitHostPort(addr)
	if err != nil {
		hostname = addr
	} else {
		port, err = strconv.ParseUint(portstr, 10, 16)
		if err != nil {
			return nil, err
		}
	}

	return ParseAddressPort(network, hostname, uint16(port)), nil
}

func ParseDomainPort(network string, addr string, port uint16) (ad Address) {
	return DomainAddr{
		hostname:       unique.Make(addr),
		port:           port,
		AddressNetwork: ParseAddressNetwork(network),
	}
}

func ParseAddressPort(network string, addr string, port uint16) (ad Address) {
	if addr, err := netip.ParseAddr(addr); err == nil {
		return IPAddr{
			AddressNetwork: ParseAddressNetwork(network),
			Addr:           addr.Unmap(),
			port:           port,
		}
	}

	return ParseDomainPort(network, addr, port)
}

func ParseIPAddr(net string, ip net.IP, port uint16) Address {
	return IPAddr{
		AddressNetwork: ParseAddressNetwork(net),
		Addr:           toAddrPort(ip, ""),
		port:           port,
	}
}

func ParseNetipAddr(net string, ip netip.Addr, port uint16) Address {
	return IPAddr{
		AddressNetwork: ParseAddressNetwork(net),
		Addr:           ip.Unmap(),
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
	if ad == nil {
		return nil, errors.New("invalid address")
	}

	switch ad := ad.(type) {
	case Address:
		return ad, nil
	case *net.TCPAddr:
		return IPAddr{
			AddressNetwork: ParseAddressNetwork(ad.Network()),
			Addr:           toAddrPort(ad.IP, ad.Zone),
			port:           uint16(ad.Port),
		}, nil
	case *net.UDPAddr:
		return IPAddr{
			AddressNetwork: ParseAddressNetwork(ad.Network()),
			Addr:           toAddrPort(ad.IP, ad.Zone),
			port:           uint16(ad.Port),
		}, nil
	case *net.IPAddr:
		return IPAddr{
			AddressNetwork: ParseAddressNetwork(ad.Network()),
			Addr:           toAddrPort(ad.IP, ad.Zone),
			port:           0,
		}, nil
	case *net.UnixAddr:
		return DomainAddr{
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

var _ Address = DomainAddr{}

type DomainAddr struct {
	hostname unique.Handle[string]
	AddressNetwork
	port uint16
}

func (d DomainAddr) String() string {
	return net.JoinHostPort(d.hostname.Value(), strconv.Itoa(int(d.port)))
}
func (d DomainAddr) Hostname() string                      { return d.hostname.Value() }
func (d DomainAddr) Port() uint16                          { return d.port }
func (d DomainAddr) IsFqdn() bool                          { return true }
func (d DomainAddr) UniqueHostname() unique.Handle[string] { return d.hostname }
func (d DomainAddr) Comparable() uint64                    { return ComputeAddressHash(d) }

var _ IPAddress = IPAddr{}

type IPAddr struct {
	Addr netip.Addr
	AddressNetwork
	port uint16
}

func (d IPAddr) String() string     { return net.JoinHostPort(d.Addr.String(), strconv.Itoa(int(d.port))) }
func (d IPAddr) Hostname() string   { return d.Addr.String() }
func (d IPAddr) Port() uint16       { return d.port }
func (d IPAddr) IsFqdn() bool       { return false }
func (d IPAddr) IP() net.IP         { return d.Addr.AsSlice() }
func (d IPAddr) Comparable() uint64 { return ComputeAddressHash(d) }

var EmptyAddr Address = DomainAddr{hostname: unique.Make("")}
