package netapi

import (
	"net"
	"net/netip"
	"strconv"

	"github.com/Asutorufa/yuhaiin/pkg/log"
)

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
		hostname: addr,
		port:     port,
		network:  network,
	}
}

func ParseAddressPort(network string, addr string, port uint16) (ad Address) {
	if addr, err := netip.ParseAddr(addr); err == nil {
		return &IPAddr{
			network: network,
			ip:      addr.Unmap(),
			port:    port,
		}
	}

	return ParseDomainPort(network, addr, port)
}

func ParseIPAddrPort(net string, ip net.IP, port uint16) Address {
	return &IPAddr{
		network: net,
		ip:      toAddrPort(ip, ""),
		port:    port,
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
			network: ad.Network(),
			ip:      toAddrPort(ad.IP, ad.Zone),
			port:    uint16(ad.Port),
		}, nil
	case *net.UDPAddr:
		return &IPAddr{
			network: ad.Network(),
			ip:      toAddrPort(ad.IP, ad.Zone),
			port:    uint16(ad.Port),
		}, nil
	case *net.IPAddr:
		return &IPAddr{
			network: ad.Network(),
			ip:      toAddrPort(ad.IP, ad.Zone),
			port:    0,
		}, nil
	case *net.UnixAddr:
		return &DomainAddr{
			hostname: ad.Name,
			network:  ad.Network(),
		}, nil
	}
	return ParseAddress(ad.Network(), ad.String())
}

var _ Address = (*DomainAddr)(nil)

type DomainAddr struct {
	network  string
	hostname string
	port     uint16
}

func (d *DomainAddr) Network() string  { return d.network }
func (d *DomainAddr) String() string   { return net.JoinHostPort(d.hostname, strconv.Itoa(int(d.port))) }
func (d *DomainAddr) Hostname() string { return d.hostname }
func (d *DomainAddr) Port() uint16     { return d.port }
func (d *DomainAddr) IsFqdn() bool     { return true }
func (d *DomainAddr) Equal(o Address) bool {
	x, ok := o.(*DomainAddr)
	if !ok {
		return false
	}
	return x.hostname == d.hostname && x.port == d.port
}

var _ IPAddress = (*IPAddr)(nil)

type IPAddr struct {
	ip      netip.Addr
	network string
	port    uint16
}

func (d *IPAddr) Network() string      { return d.network }
func (d *IPAddr) String() string       { return net.JoinHostPort(d.ip.String(), strconv.Itoa(int(d.port))) }
func (d *IPAddr) Hostname() string     { return d.ip.String() }
func (d *IPAddr) Port() uint16         { return d.port }
func (d *IPAddr) IsFqdn() bool         { return false }
func (d *IPAddr) IP() net.IP           { return d.ip.AsSlice() }
func (d *IPAddr) WithZone(zone string) { d.ip = d.ip.WithZone(zone) }
func (d *IPAddr) Equal(o Address) bool {
	x, ok := o.(*IPAddr)
	if !ok {
		return false
	}
	return x.ip.Compare(d.ip) == 0 && x.port == d.port
}

var EmptyAddr Address = &DomainAddr{}
