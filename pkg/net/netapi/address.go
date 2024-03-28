package netapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"strconv"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"golang.org/x/exp/constraints"
)

func PaseNetwork(s string) statistic.Type { return statistic.Type(statistic.Type_value[s]) }

func ParseAddress(network statistic.Type, addr string) (ad Address, _ error) {
	hostname, portstr, err := net.SplitHostPort(addr)
	if err != nil {
		log.Error("split host port failed", "err", err, "addr", addr)
		hostname = addr
		portstr = "0"
	}

	port, err := ParsePortStr(portstr)
	if err != nil {
		return nil, fmt.Errorf("parse port failed: %w", err)
	}

	return ParseAddressPort(network, hostname, port), nil
}

func ParseDomainPort(network statistic.Type, addr string, port Port) (ad Address) {
	return &DomainAddr{
		hostname: addr,
		port:     port,
		addr:     newAddr(network),
	}
}

func ParseAddressPort(network statistic.Type, addr string, port Port) (ad Address) {
	if addr, err := netip.ParseAddr(addr); err == nil {
		return &IPAddrPort{
			addr:     newAddr(network),
			addrPort: netip.AddrPortFrom(addr.Unmap(), port.Port()),
		}
	}

	return ParseDomainPort(network, addr, port)
}

func ParseTCPAddress(ad *net.TCPAddr) Address {
	addrPort := ad.AddrPort()
	return &IPAddrPort{
		addr:     newAddr(statistic.Type_tcp),
		addrPort: netip.AddrPortFrom(addrPort.Addr().Unmap(), addrPort.Port()),
	}
}

func ParseUDPAddr(ad *net.UDPAddr) Address {
	addrPort := ad.AddrPort()
	return &IPAddrPort{
		addr:     newAddr(statistic.Type_udp),
		addrPort: netip.AddrPortFrom(addrPort.Addr().Unmap(), addrPort.Port()),
	}
}

func ParseIPAddr(ad *net.IPAddr) Address {
	addr, _ := netip.AddrFromSlice(ad.IP)
	addr.WithZone(ad.Zone)
	return &IPAddrPort{
		addr:     newAddr(statistic.Type_ip),
		addrPort: netip.AddrPortFrom(addr.Unmap(), 0),
	}
}

func ParseUnixAddr(ad *net.UnixAddr) Address {
	return &DomainAddr{
		hostname: ad.Name,
		port:     EmptyPort,
		addr:     newAddr(statistic.Type_unix),
	}
}

func ParseAddrPort(net statistic.Type, addrPort netip.AddrPort) Address {
	return &IPAddrPort{
		addrPort: addrPort,
		addr:     newAddr(net),
	}
}

func ParseSysAddr(ad net.Addr) (Address, error) {
	switch ad := ad.(type) {
	case Address:
		return ad, nil
	case *net.TCPAddr:
		return ParseTCPAddress(ad), nil
	case *net.UDPAddr:
		return ParseUDPAddr(ad), nil
	case *net.IPAddr:
		return ParseIPAddr(ad), nil
	case *net.UnixAddr:
		return ParseUnixAddr(ad), nil
	}
	return ParseAddress(PaseNetwork(ad.Network()), ad.String())
}

type addr struct {
	network    statistic.Type
	src        AddressSrc
	preferIPv6 bool
	preferIPv4 bool
	resolver   Resolver
}

func newAddr(net statistic.Type) *addr {
	return &addr{
		network: net,
	}
}

func (d *addr) SetSrc(src AddressSrc) {
	d.src = src
}

func (d *addr) SetResolver(resolver Resolver) {
	if resolver == nil {
		return
	}

	if d.resolver != nil && d.src == AddressSrcDNS {
		return
	}

	d.resolver = resolver
}

func (d *addr) Resolver() Resolver {
	if d.resolver != nil {
		return d.resolver
	}

	return Bootstrap
}

func (d *addr) Network() string             { return d.network.String() }
func (d *addr) NetworkType() statistic.Type { return d.network }
func (d *addr) PreferIPv6(b bool)           { d.preferIPv6 = b }
func (d *addr) PreferIPv4(b bool)           { d.preferIPv4 = b }
func (d *addr) overrideHostname(s string, port Port) Address {
	if addr, err := netip.ParseAddr(s); err == nil {
		return &IPAddrPort{
			addr:     d,
			addrPort: netip.AddrPortFrom(addr, port.Port()),
		}
	}

	return &DomainAddr{
		hostname: s,
		addr:     d,
		port:     port,
	}
}

var _ Address = (*DomainAddr)(nil)

type DomainAddr struct {
	*addr
	port     Port
	hostname string
}

func (d *DomainAddr) String() string   { return net.JoinHostPort(d.Hostname(), d.Port().String()) }
func (d *DomainAddr) Hostname() string { return d.hostname }
func (d *DomainAddr) IPs(ctx context.Context) ([]net.IP, error) {
	return d.lookupIP(ctx)
}

func (d *DomainAddr) IP(ctx context.Context) (net.IP, error) {
	ip, err := d.lookupIP(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve address %s failed: %w", d.hostname, err)
	}

	return ip[rand.IntN(len(ip))], nil
}

func (d *DomainAddr) AddrPort(ctx context.Context) Result[netip.AddrPort] {
	ip, err := d.IP(ctx)
	if err != nil {
		return NewErrResult[netip.AddrPort](fmt.Errorf("resolve address %s failed: %w", d.hostname, err))
	}

	addr, _ := netip.AddrFromSlice(ip)

	return NewResult(netip.AddrPortFrom(addr, d.port.Port()))
}

func (d *DomainAddr) Port() Port   { return d.port }
func (d *DomainAddr) Type() Type   { return FQDN }
func (d *DomainAddr) IsFqdn() bool { return true }
func (d *DomainAddr) lookupIP(ctx context.Context) ([]net.IP, error) {
	if d.preferIPv6 || d.preferIPv4 {
		ips, err := d.Resolver().LookupIP(ctx, d.hostname, func(li *LookupIPOption) {
			if d.preferIPv6 {
				li.AAAA = true
				li.A = false
			}
			if d.preferIPv4 {
				li.A = true
				li.AAAA = false
			}
		})
		if err == nil {
			return ips, nil
		} else {
			log.Warn("resolve ipv6 failed, fallback to ipv4", slog.String("domain", d.hostname), slog.Any("err", err))
		}
	}

	ips, err := d.Resolver().LookupIP(ctx, d.hostname)
	if err != nil {
		return nil, fmt.Errorf("resolve address failed: %w", err)
	}

	return ips, nil
}

func (d *DomainAddr) UDPAddr(ctx context.Context) Result[*net.UDPAddr] {
	ip, err := d.lookupIP(ctx)
	if err != nil {
		return NewErrResult[*net.UDPAddr](fmt.Errorf("resolve udp address %s failed: %w", d.hostname, err))
	}

	return NewResult(&net.UDPAddr{IP: ip[rand.IntN(len(ip))], Port: int(d.port.Port())})
}

func (d *DomainAddr) TCPAddr(ctx context.Context) Result[*net.TCPAddr] {
	ip, err := d.lookupIP(ctx)
	if err != nil {
		return NewErrResult[*net.TCPAddr](fmt.Errorf("resolve tcp address %s failed: %w", d.hostname, err))
	}

	return NewResult(&net.TCPAddr{IP: ip[rand.IntN(len(ip))], Port: int(d.port.Port())})
}

func (d *DomainAddr) OverrideHostname(s string) Address {
	return d.addr.overrideHostname(s, d.port)
}

func (d *DomainAddr) OverridePort(p Port) Address {
	return &DomainAddr{
		hostname: d.Hostname(),
		addr:     d.addr,
		port:     p,
	}
}

var _ Address = (*IPAddrPort)(nil)

type IPAddrPort struct {
	addrPort netip.AddrPort
	*addr
}

func (d *IPAddrPort) String() string                                  { return d.addrPort.String() }
func (d *IPAddrPort) Hostname() string                                { return d.addrPort.Addr().String() }
func (d *IPAddrPort) AddrPort(context.Context) Result[netip.AddrPort] { return NewResult(d.addrPort) }
func (d *IPAddrPort) IPs(context.Context) ([]net.IP, error) {
	return []net.IP{d.addrPort.Addr().AsSlice()}, nil
}
func (d *IPAddrPort) IP(context.Context) (net.IP, error) { return d.addrPort.Addr().AsSlice(), nil }
func (d *IPAddrPort) Port() Port                         { return ParsePort(d.addrPort.Port()) }
func (d *IPAddrPort) Type() Type                         { return IP }
func (d *IPAddrPort) IsFqdn() bool                       { return false }
func (d *IPAddrPort) UDPAddr(context.Context) Result[*net.UDPAddr] {
	return NewResult(&net.UDPAddr{IP: d.addrPort.Addr().AsSlice(), Port: int(d.addrPort.Port()), Zone: d.addrPort.Addr().Zone()})
}
func (d *IPAddrPort) TCPAddr(context.Context) Result[*net.TCPAddr] {
	return NewResult(&net.TCPAddr{IP: d.addrPort.Addr().AsSlice(), Port: int(d.addrPort.Port()), Zone: d.addrPort.Addr().Zone()})
}
func (d *IPAddrPort) OverrideHostname(s string) Address { return d.overrideHostname(s, d.Port()) }
func (d *IPAddrPort) OverridePort(p Port) Address {
	return &IPAddrPort{
		addr:     d.addr,
		addrPort: netip.AddrPortFrom(d.addrPort.Addr(), p.Port()),
	}
}

var EmptyAddr Address = &emptyAddr{}

type emptyAddr struct{}

func (d emptyAddr) String() string                        { return "" }
func (d emptyAddr) Hostname() string                      { return "" }
func (d emptyAddr) IPs(context.Context) ([]net.IP, error) { return nil, errors.New("empty") }
func (d emptyAddr) IP(context.Context) (net.IP, error)    { return nil, errors.New("empty") }
func (d emptyAddr) AddrPort(context.Context) Result[netip.AddrPort] {
	return NewErrResult[netip.AddrPort](errors.New("empty"))
}
func (d emptyAddr) Port() Port                  { return EmptyPort }
func (d emptyAddr) Network() string             { return "" }
func (d emptyAddr) NetworkType() statistic.Type { return 0 }
func (d emptyAddr) Type() Type                  { return EMPTY }
func (d emptyAddr) IsFqdn() bool                { return false }
func (d emptyAddr) SetSrc(AddressSrc)           {}
func (d emptyAddr) SetResolver(Resolver)        {}
func (d emptyAddr) PreferIPv6(bool)             {}
func (d emptyAddr) PreferIPv4(bool)             {}
func (d emptyAddr) UDPAddr(context.Context) Result[*net.UDPAddr] {
	return NewErrResult[*net.UDPAddr](errors.New("empty"))
}
func (d emptyAddr) TCPAddr(context.Context) Result[*net.TCPAddr] {
	return NewErrResult[*net.TCPAddr](errors.New("empty"))
}
func (d emptyAddr) IPHost(context.Context) (string, error) { return "", errors.New("empty") }
func (d emptyAddr) WithValue(any, any)                     {}
func (d emptyAddr) Value(any) (any, bool)                  { return nil, false }
func (d emptyAddr) RangeValue(func(any, any) bool)         {}
func (d emptyAddr) OverrideHostname(string) Address        { return d }
func (d emptyAddr) OverridePort(Port) Address              { return d }

type PortUint16 uint16

func (p PortUint16) Port() uint16   { return uint16(p) }
func (p PortUint16) String() string { return strconv.FormatUint(uint64(p), 10) }

var EmptyPort Port = PortUint16(0)

func ParsePort[T constraints.Integer](p T) Port { return PortUint16(p) }

func ParsePortStr(p string) (Port, error) {
	pt, err := strconv.ParseUint(p, 10, 16)
	if err != nil {
		return nil, err
	}

	return PortUint16(pt), nil
}
