package proxy

import (
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
	_ "unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/yerror"
	"golang.org/x/exp/constraints"
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

var DiscardProxy Proxy = &Discard{}

type Discard struct{}

func (Discard) Conn(Address) (net.Conn, error)             { return DiscardNetConn, nil }
func (Discard) PacketConn(Address) (net.PacketConn, error) { return DiscardNetPacketConn, nil }

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

type errProxy struct{ error }

func NewErrProxy(err error) Proxy                             { return &errProxy{err} }
func (e errProxy) Conn(Address) (net.Conn, error)             { return nil, e.error }
func (e errProxy) PacketConn(Address) (net.PacketConn, error) { return nil, e.error }

type ResolverProxy interface {
	Resolver(Address) dns.DNS
}
type DialerResolverProxy interface {
	Proxy
	ResolverProxy
}

type resolverProxy struct{ dns.DNS }

func WrapDNS(d dns.DNS) ResolverProxy             { return &resolverProxy{d} }
func (r *resolverProxy) Resolver(Address) dns.DNS { return r.DNS }

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
	IP() (net.IP, error)
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

	Zone() string // IPv6 scoped addressing zone
	UDPAddr() (*net.UDPAddr, error)
	TCPAddr() (*net.TCPAddr, error)
	// IPHost if address is ip, return host, else resolve domain to ip and return JoinHostPort(ip,port)
	IPHost() (string, error)

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
	hostname, ports, err := net.SplitHostPort(addr)
	if err != nil {
		log.Errorf("split host port failed: %v\n", err)
		hostname = addr
		ports = "0"
	}

	port, err := ParsePortStr(ports)
	if err != nil {
		return nil, fmt.Errorf("parse port failed: %w", err)
	}

	return ParseAddressSplit(network, hostname, port), nil
}

//go:linkname ParseIPZone net.parseIPZone
func ParseIPZone(s string) (net.IP, string)

func ParseAddressSplit(network statistic.Type, addr string, port Port) (ad Address) {
	i, zone := ParseIPZone(addr)
	if i != nil {
		addr = i.String()
	} else {
		addr = strings.ToLower(addr)
	}

	if port == nil {
		port = EmptyPort
	}

	ad = &DomainAddr{
		hostname: addr,
		port:     port,
		network:  network,
	}

	if i != nil {
		ad = &IPAddr{ad, zone}
	}

	return
}

func ParseTCPAddress(ad *net.TCPAddr) Address {
	return &IPAddr{
		Address: &DomainAddr{
			hostname: ad.IP.String(),
			port:     ParsePort(ad.Port),
			network:  statistic.Type_tcp,
		},
		zone: ad.Zone,
	}
}

func ParseUDPAddr(ad *net.UDPAddr) Address {
	return &IPAddr{
		Address: &DomainAddr{
			hostname: ad.IP.String(),
			port:     ParsePort(ad.Port),
			network:  statistic.Type_udp,
		},
		zone: ad.Zone,
	}
}

func ParseIPAddr(ad *net.IPAddr) Address {
	return &IPAddr{
		Address: &DomainAddr{
			hostname: ad.IP.String(),
			port:     EmptyPort,
			network:  statistic.Type_ip,
		},
		zone: ad.Zone,
	}
}

func ParseUnixAddr(ad *net.UnixAddr) Address {
	return &DomainAddr{
		hostname: ad.Name,
		port:     EmptyPort,
		network:  statistic.Type_unix,
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

var _ Address = (*DomainAddr)(nil)

type DomainAddr struct {
	network  statistic.Type
	port     Port
	hostname string
	lock     sync.RWMutex
	store    map[any]any
}

func (d *DomainAddr) String() string   { return net.JoinHostPort(d.Hostname(), d.Port().String()) }
func (d *DomainAddr) Hostname() string { return d.hostname }
func (d *DomainAddr) IP() (net.IP, error) {
	ip, err := d.lookupIP()
	if err != nil {
		return nil, fmt.Errorf("resolve address %s failed: %w", d.hostname, err)
	}

	return ip, nil
}
func (d *DomainAddr) Port() Port                  { return d.port }
func (d *DomainAddr) Network() string             { return d.network.String() }
func (d *DomainAddr) NetworkType() statistic.Type { return d.network }
func (d *DomainAddr) Type() Type                  { return DOMAIN }
func (d *DomainAddr) WithResolver(resolver dns.DNS, canCover bool) bool {
	if !Value(d, resolverCanCoverKey{}, true) {
		return false
	}

	d.WithValue(resolverKey{}, resolver)
	d.WithValue(resolverCanCoverKey{}, canCover)
	return true
}
func (d *DomainAddr) Zone() string { return "" }
func (d *DomainAddr) lookupIP() (net.IP, error) {
	ips, err := Value(d, resolverKey{}, resolver.Bootstrap).LookupIP(d.hostname)
	if err != nil {
		return nil, fmt.Errorf("resolve address failed: %w", err)
	}

	return ips[rand.Intn(len(ips))], nil
}

func (d *DomainAddr) UDPAddr() (*net.UDPAddr, error) {
	ip, err := d.lookupIP()
	if err != nil {
		return nil, fmt.Errorf("resolve udp address %s failed: %w", d.hostname, err)
	}

	return &net.UDPAddr{IP: ip, Port: int(d.port.Port())}, nil
}

func (d *DomainAddr) TCPAddr() (*net.TCPAddr, error) {
	ip, err := d.lookupIP()
	if err != nil {
		return nil, fmt.Errorf("resolve tcp address %s failed: %w", d.hostname, err)
	}

	return &net.TCPAddr{IP: ip, Port: int(d.port.Port())}, nil
}
func (d *DomainAddr) IPHost() (string, error) {
	ip, err := d.IP()
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(ip.String(), d.port.String()), nil
}

func (d *DomainAddr) OverrideHostname(s string) Address {
	z, zone := ParseIPZone(s)
	if z != nil {
		s = z.String()
	} else {
		s = strings.ToLower(s)
	}

	r := &DomainAddr{
		hostname: s,
		store:    d.store,
		port:     d.port,
		network:  d.network,
	}

	if z == nil {
		return r
	}

	return &IPAddr{Address: r, zone: zone}
}

func (d *DomainAddr) OverridePort(p Port) Address {
	return &DomainAddr{
		hostname: d.Hostname(),
		store:    d.store,
		port:     p,
		network:  d.network,
	}
}

func (s *DomainAddr) WithValue(key, value any) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.store == nil {
		s.store = make(map[any]any)
	}

	s.store[key] = value
}

func (s *DomainAddr) Value(key any) (any, bool) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	if s.store == nil {
		return nil, false
	}
	v, ok := s.store[key]
	return v, ok
}

func (s *DomainAddr) RangeValue(f func(k, v any) bool) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	for k, v := range s.store {
		if !f(k, v) {
			break
		}
	}
}

var _ Address = (*IPAddr)(nil)

type IPAddr struct {
	Address
	zone string
}

func (i IPAddr) IP() (net.IP, error) { return net.ParseIP(i.Hostname()), nil }
func (i IPAddr) Type() Type          { return IP }
func (i IPAddr) Zone() string        { return i.zone }
func (i IPAddr) UDPAddr() (*net.UDPAddr, error) {
	return &net.UDPAddr{IP: yerror.Must(i.IP()), Port: int(i.Port().Port()), Zone: i.zone}, nil
}
func (i IPAddr) OverridePort(p Port) Address {
	return &IPAddr{
		Address: i.Address.OverridePort(p),
		zone:    i.zone,
	}
}
func (i IPAddr) TCPAddr() (*net.TCPAddr, error) {
	return &net.TCPAddr{IP: yerror.Must(i.IP()), Port: int(i.Port().Port()), Zone: i.zone}, nil
}
func (i IPAddr) IPHost() (string, error) { return i.String(), nil }

var EmptyAddr Address = &emptyAddr{}

type emptyAddr struct{}

func (d emptyAddr) String() string                  { return "" }
func (d emptyAddr) Hostname() string                { return "" }
func (d emptyAddr) IP() (net.IP, error)             { return nil, errors.New("empty") }
func (d emptyAddr) Port() Port                      { return EmptyPort }
func (d emptyAddr) Network() string                 { return "" }
func (d emptyAddr) NetworkType() statistic.Type     { return 0 }
func (d emptyAddr) Type() Type                      { return EMPTY }
func (d emptyAddr) WithResolver(dns.DNS, bool) bool { return false }
func (d emptyAddr) Zone() string                    { return "" }
func (d emptyAddr) UDPAddr() (*net.UDPAddr, error)  { return nil, errors.New("empty") }
func (d emptyAddr) TCPAddr() (*net.TCPAddr, error)  { return nil, errors.New("empty") }
func (d emptyAddr) IPHost() (string, error)         { return "", errors.New("empty") }
func (d emptyAddr) WithValue(any, any)              {}
func (d emptyAddr) Value(any) (any, bool)           { return nil, false }
func (d emptyAddr) RangeValue(func(any, any) bool)  {}
func (d emptyAddr) OverrideHostname(string) Address { return d }
func (d emptyAddr) OverridePort(Port) Address       { return d }

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
