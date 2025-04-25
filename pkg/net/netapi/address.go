package netapi

import (
	"errors"
	"hash/maphash"
	"net"
	"net/netip"
	"strconv"
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
	AddrPort() netip.AddrPort
}

type DomainAddress interface{ Address }

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
		Hostname_:      addr,
		Port_:          port,
		AddressNetwork: ParseAddressNetwork(network),
	}
}

func ParseAddressPort(network string, addr string, port uint16) (ad Address) {
	if addr, err := netip.ParseAddr(addr); err == nil {
		return IPAddr{
			AddressNetwork: ParseAddressNetwork(network),
			AddrPort_:      netip.AddrPortFrom(addr.Unmap(), port),
		}
	}

	return ParseDomainPort(network, addr, port)
}

func ParseIPAddr(net string, ip net.IP, port uint16) Address {
	return IPAddr{
		AddressNetwork: ParseAddressNetwork(net),
		AddrPort_:      toAddrPort(ip, port, ""),
	}
}

func ParseNetipAddr(net string, ip netip.Addr, port uint16) Address {
	return IPAddr{
		AddressNetwork: ParseAddressNetwork(net),
		AddrPort_:      netip.AddrPortFrom(ip, port),
	}
}

func toAddrPort(ad net.IP, port uint16, zone string) netip.AddrPort {
	addr, _ := netip.AddrFromSlice(ad)
	addr = addr.Unmap()
	if zone != "" {
		addr = addr.WithZone(zone)
	}

	return netip.AddrPortFrom(addr, port)
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
			AddrPort_:      toAddrPort(ad.IP, uint16(ad.Port), ad.Zone),
		}, nil
	case *net.UDPAddr:
		return IPAddr{
			AddressNetwork: ParseAddressNetwork(ad.Network()),
			AddrPort_:      toAddrPort(ad.IP, uint16(ad.Port), ad.Zone),
		}, nil
	case *net.IPAddr:
		return IPAddr{
			AddressNetwork: ParseAddressNetwork(ad.Network()),
			AddrPort_:      toAddrPort(ad.IP, 0, ad.Zone),
		}, nil
	case *net.UnixAddr:
		return DomainAddr{
			Hostname_:      ad.Name,
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
	Hostname_      string `json:"hostname,omitempty"`
	AddressNetwork `json:"network,omitempty"`
	Port_          uint16 `json:"port,omitempty"`
}

func (d DomainAddr) String() string {
	return net.JoinHostPort(d.Hostname_, strconv.Itoa(int(d.Port_)))
}
func (d DomainAddr) Hostname() string   { return d.Hostname_ }
func (d DomainAddr) Port() uint16       { return d.Port_ }
func (d DomainAddr) IsFqdn() bool       { return true }
func (d DomainAddr) Comparable() uint64 { return ComputeAddressHash(d) }

var _ IPAddress = IPAddr{}

type IPAddr struct {
	AddrPort_      netip.AddrPort `json:"addr_port,omitempty"`
	AddressNetwork `json:"network,omitempty"`
}

func (d IPAddr) String() string           { return d.AddrPort_.String() }
func (d IPAddr) Hostname() string         { return d.AddrPort_.Addr().String() }
func (d IPAddr) Port() uint16             { return d.AddrPort_.Port() }
func (d IPAddr) IsFqdn() bool             { return false }
func (d IPAddr) AddrPort() netip.AddrPort { return d.AddrPort_ }
func (d IPAddr) Comparable() uint64       { return ComputeAddressHash(d) }

var EmptyAddr Address = DomainAddr{}
