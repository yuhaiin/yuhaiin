package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"golang.org/x/exp/constraints"
	"golang.org/x/net/dns/dnsmessage"
)

type Proxy interface {
	StreamProxy
	PacketProxy
	Dispatch(context.Context, Address) (Address, error)
}

type StreamProxy interface {
	Conn(context.Context, Address) (net.Conn, error)
}

type PacketProxy interface {
	PacketConn(context.Context, Address) (net.PacketConn, error)
}

type EmptyDispatch struct{}

func (EmptyDispatch) Dispatch(_ context.Context, a Address) (Address, error) { return a, nil }

var DiscardProxy Proxy = &Discard{}

type Discard struct{ EmptyDispatch }

func (Discard) Conn(context.Context, Address) (net.Conn, error) { return DiscardNetConn, nil }
func (Discard) PacketConn(context.Context, Address) (net.PacketConn, error) {
	return DiscardNetPacketConn, nil
}

var DiscardNetConn net.Conn = &DiscardConn{}

type DiscardConn struct{}

func (*DiscardConn) Read(b []byte) (n int, err error)   { return 0, io.EOF }
func (*DiscardConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (*DiscardConn) Close() error                       { return nil }
func (*DiscardConn) LocalAddr() net.Addr                { return EmptyAddr }
func (*DiscardConn) RemoteAddr() net.Addr               { return EmptyAddr }
func (*DiscardConn) SetDeadline(t time.Time) error      { return nil }
func (*DiscardConn) SetReadDeadline(t time.Time) error  { return nil }
func (*DiscardConn) SetWriteDeadline(t time.Time) error { return nil }

var DiscardNetPacketConn net.PacketConn = &DiscardPacketConn{}

type DiscardPacketConn struct{}

func (*DiscardPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	return 0, EmptyAddr, io.EOF
}
func (*DiscardPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return len(p), nil
}
func (*DiscardPacketConn) Close() error                       { return nil }
func (*DiscardPacketConn) LocalAddr() net.Addr                { return EmptyAddr }
func (*DiscardPacketConn) SetDeadline(t time.Time) error      { return nil }
func (*DiscardPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (*DiscardPacketConn) SetWriteDeadline(t time.Time) error { return nil }

type errProxy struct {
	EmptyDispatch
	error
}

func NewErrProxy(err error) Proxy                                              { return &errProxy{error: err} }
func (e errProxy) Conn(context.Context, Address) (net.Conn, error)             { return nil, e.error }
func (e errProxy) PacketConn(context.Context, Address) (net.PacketConn, error) { return nil, e.error }

func PaseNetwork(s string) statistic.Type { return statistic.Type(statistic.Type_value[s]) }

type Type uint8

func (t Type) String() string {
	switch t {
	case DOMAIN:
		return "DOMAIN"
	case IP:
		return "IP"
	case UNIX:
		return "UNIX"
	case EMPTY:
		return "EMPTY"
	default:
		return "UNKNOWN"
	}
}

const (
	DOMAIN Type = 1
	IP     Type = 2
	UNIX   Type = 3
	EMPTY  Type = 4
)

type Port interface {
	Port() uint16
	String() string
}

type resolverKey struct{}
type resolverCanCoverKey struct{}

type Address interface {
	// Hostname return hostname of address, eg: www.example.com, 127.0.0.1, ff::ff
	Hostname() string
	// IP return net.IP, if address is ip else resolve the domain and return one of ips
	IP(context.Context) (net.IP, error)
	AddrPort(context.Context) (netip.AddrPort, error)
	// Port return port of address
	Port() Port
	// Type return type of address, domain or ip
	Type() Type
	NetworkType() statistic.Type

	net.Addr

	// WithResolver will use call IP(), IPHost(), UDPAddr(), TCPAddr()
	// return the current resolver is applied, if can't cover return false
	WithResolver(_ dns.DNS, canCover bool) bool
	// OverrideHostname clone address(exclude Values) and change hostname
	OverrideHostname(string) Address
	OverridePort(Port) Address

	UDPAddr(context.Context) (*net.UDPAddr, error)
	TCPAddr(context.Context) (*net.TCPAddr, error)

	WithValue(key, value any)
	Value(key any) (any, bool)
	RangeValue(func(k, v any) bool)
}

func Value[T any](s interface{ Value(any) (any, bool) }, k any, Default T) T {
	z, ok := s.Value(k)
	if !ok {
		return Default
	}

	x, ok := z.(T)
	if !ok {
		return Default
	}

	return x
}

func ParseAddress(network statistic.Type, addr string) (ad Address, _ error) {
	hostname, portstr, err := net.SplitHostPort(addr)
	if err != nil {
		log.Errorf("split host port failed: %v\n", err)
		hostname = addr
		portstr = "0"
	}

	port, err := ParsePortStr(portstr)
	if err != nil {
		return nil, fmt.Errorf("parse port failed: %w", err)
	}

	return ParseAddressPort(network, hostname, port), nil
}

func ParseAddressPort(network statistic.Type, addr string, port Port) (ad Address) {
	base := newAddr(network)

	if addr, err := netip.ParseAddr(addr); err == nil {
		return &IPAddrPort{
			addr:     base,
			addrPort: netip.AddrPortFrom(addr, port.Port()),
		}
	}

	return &DomainAddr{
		hostname: addr,
		port:     port,
		addr:     base,
	}
}

func ParseTCPAddress(ad *net.TCPAddr) Address {
	return &IPAddrPort{
		addr:     newAddr(statistic.Type_udp),
		addrPort: ad.AddrPort(),
	}
}

func ParseUDPAddr(ad *net.UDPAddr) Address {
	return &IPAddrPort{
		addr:     newAddr(statistic.Type_udp),
		addrPort: ad.AddrPort(),
	}
}

func ParseIPAddr(ad *net.IPAddr) Address {
	addr, _ := netip.AddrFromSlice(ad.IP)
	addr.WithZone(ad.Zone)
	return &IPAddrPort{
		addr:     newAddr(statistic.Type_ip),
		addrPort: netip.AddrPortFrom(addr, 0),
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
	network statistic.Type
	mu      sync.RWMutex
	store   map[any]any
}

func newAddr(net statistic.Type) *addr {
	return &addr{
		network: net,
		store:   make(map[any]any),
	}
}

func (d *addr) WithResolver(resolver dns.DNS, canCover bool) bool {
	if !Value(d, resolverCanCoverKey{}, true) {
		return false
	}

	d.WithValue(resolverKey{}, resolver)
	d.WithValue(resolverCanCoverKey{}, canCover)
	return true
}

func (s *addr) WithValue(key, value any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.store == nil {
		s.store = make(map[any]any)
	}

	s.store[key] = value
}

func (s *addr) Value(key any) (any, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.store == nil {
		return nil, false
	}
	v, ok := s.store[key]
	return v, ok
}

func (s *addr) RangeValue(f func(k, v any) bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for k, v := range s.store {
		if !f(k, v) {
			break
		}
	}
}

func (d *addr) Network() string             { return d.network.String() }
func (d *addr) NetworkType() statistic.Type { return d.network }

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
func (d *DomainAddr) IP(ctx context.Context) (net.IP, error) {
	ip, err := d.lookupIP(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve address %s failed: %w", d.hostname, err)
	}

	return ip, nil
}

func (d *DomainAddr) AddrPort(ctx context.Context) (netip.AddrPort, error) {
	ip, err := d.IP(ctx)
	if err != nil {
		return netip.AddrPort{}, err
	}

	addr, _ := netip.AddrFromSlice(ip)
	return netip.AddrPortFrom(addr, d.port.Port()), nil
}

func (d *DomainAddr) Port() Port { return d.port }
func (d *DomainAddr) Type() Type { return DOMAIN }
func (d *DomainAddr) lookupIP(ctx context.Context) (net.IP, error) {
	r := Value(d, resolverKey{}, resolver.Bootstrap)

	if Value(d, PreferIPv6{}, false) {
		ip, err := r.Record(ctx, d.hostname, dnsmessage.TypeAAAA)
		if err == nil {
			return ip.IPs[rand.Intn(len(ip.IPs))], nil
		} else {
			log.Warningf("resolve %s ipv6 failed: %w, fallback to ipv4\n", d.hostname, err)
		}
	}

	ips, err := r.LookupIP(ctx, d.hostname)
	if err != nil {
		return nil, fmt.Errorf("resolve address failed: %w", err)
	}

	return ips[rand.Intn(len(ips))], nil
}

func (d *DomainAddr) UDPAddr(ctx context.Context) (*net.UDPAddr, error) {
	ip, err := d.lookupIP(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve udp address %s failed: %w", d.hostname, err)
	}

	return &net.UDPAddr{IP: ip, Port: int(d.port.Port())}, nil
}

func (d *DomainAddr) TCPAddr(ctx context.Context) (*net.TCPAddr, error) {
	ip, err := d.lookupIP(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve tcp address %s failed: %w", d.hostname, err)
	}

	return &net.TCPAddr{IP: ip, Port: int(d.port.Port())}, nil
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

func (d *IPAddrPort) String() string                                   { return d.addrPort.String() }
func (d *IPAddrPort) Hostname() string                                 { return d.addrPort.Addr().String() }
func (d *IPAddrPort) AddrPort(context.Context) (netip.AddrPort, error) { return d.addrPort, nil }
func (d *IPAddrPort) IP(context.Context) (net.IP, error)               { return d.addrPort.Addr().AsSlice(), nil }
func (d *IPAddrPort) Port() Port                                       { return ParsePort(d.addrPort.Port()) }
func (d *IPAddrPort) Type() Type                                       { return IP }
func (d *IPAddrPort) UDPAddr(context.Context) (*net.UDPAddr, error) {
	return &net.UDPAddr{
		IP:   d.addrPort.Addr().AsSlice(),
		Port: int(d.addrPort.Port()),
		Zone: d.addrPort.Addr().Zone(),
	}, nil
}
func (d *IPAddrPort) TCPAddr(context.Context) (*net.TCPAddr, error) {
	return &net.TCPAddr{
		IP:   d.addrPort.Addr().AsSlice(),
		Port: int(d.addrPort.Port()),
		Zone: d.addrPort.Addr().Zone(),
	}, nil
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

func (d emptyAddr) String() string                     { return "" }
func (d emptyAddr) Hostname() string                   { return "" }
func (d emptyAddr) IP(context.Context) (net.IP, error) { return nil, errors.New("empty") }
func (d emptyAddr) AddrPort(context.Context) (netip.AddrPort, error) {
	return netip.AddrPort{}, errors.New("empty")
}
func (d emptyAddr) Port() Port                                    { return EmptyPort }
func (d emptyAddr) Network() string                               { return "" }
func (d emptyAddr) NetworkType() statistic.Type                   { return 0 }
func (d emptyAddr) Type() Type                                    { return EMPTY }
func (d emptyAddr) WithResolver(dns.DNS, bool) bool               { return false }
func (d emptyAddr) UDPAddr(context.Context) (*net.UDPAddr, error) { return nil, errors.New("empty") }
func (d emptyAddr) TCPAddr(context.Context) (*net.TCPAddr, error) { return nil, errors.New("empty") }
func (d emptyAddr) IPHost(context.Context) (string, error)        { return "", errors.New("empty") }
func (d emptyAddr) WithValue(any, any)                            {}
func (d emptyAddr) Value(any) (any, bool)                         { return nil, false }
func (d emptyAddr) RangeValue(func(any, any) bool)                {}
func (d emptyAddr) OverrideHostname(string) Address               { return d }
func (d emptyAddr) OverridePort(Port) Address                     { return d }
func (d emptyAddr) Context() context.Context                      { return context.TODO() }
func (d emptyAddr) WithContext(context.Context)                   {}

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

type PreferIPv6 struct{}

type SourceKey struct{}

func (SourceKey) String() string { return "Source" }

type InboundKey struct{}

func (InboundKey) String() string { return "Inbound" }

type DestinationKey struct{}

func (DestinationKey) String() string { return "Destination" }

type FakeIPKey struct{}

func (FakeIPKey) String() string { return "FakeIP" }

type CurrentKey struct{}

var ErrBlocked = errors.New("BLOCK")

type errorBlockedImpl struct {
	network statistic.Type
	h       string
}

func NewBlockError(network statistic.Type, hostname string) error {
	return &errorBlockedImpl{network, hostname}
}
func (e *errorBlockedImpl) Error() string {
	return fmt.Sprintf("blocked address %v[%s]", e.network, e.h)
}
func (e *errorBlockedImpl) Is(err error) bool { return errors.Is(err, ErrBlocked) }
