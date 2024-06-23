package netapi

import (
	"context"
	"net"
	"net/netip"

	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
)

type ProcessDumper interface {
	ProcessName(network string, src, dst Address) (string, error)
}

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

type Port interface {
	Port() uint16
	String() string
}

type Type uint8

func (t Type) String() string {
	switch t {
	case FQDN:
		return "FQDN"
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
	FQDN  Type = 1
	IP    Type = 2
	UNIX  Type = 3
	EMPTY Type = 4
)

type AddressSrc int32

const (
	AddressSrcEmpty AddressSrc = 0
	AddressSrcDNS   AddressSrc = 1
)

type Result[T any] struct {
	V   T
	Err error
}

func NewErrResult[T any](err error) Result[T] {
	return Result[T]{Err: err}
}

func NewResult[T any](v T) Result[T] {
	return Result[T]{V: v}
}

type Address interface {
	// Hostname return hostname of address, eg: www.example.com, 127.0.0.1, ff::ff
	Hostname() string
	IPs(context.Context) ([]net.IP, error)
	// IP return net.IP, if address is ip else resolve the domain and return one of ips
	IP(context.Context) (net.IP, error)
	AddrPort(context.Context) Result[netip.AddrPort]
	UDPAddr(context.Context) Result[*net.UDPAddr]
	TCPAddr(context.Context) Result[*net.TCPAddr]
	// Port return port of address
	Port() Port
	// Type return type of address, domain or ip
	Type() Type
	NetworkType() statistic.Type

	net.Addr

	SetSrc(AddressSrc)
	// SetResolver will use call IP(), IPHost(), UDPAddr(), TCPAddr()
	SetResolver(_ Resolver)
	PreferIPv6(b bool)
	PreferIPv4(b bool)
	// OverrideHostname clone address(exclude Values) and change hostname
	OverrideHostname(string) Address
	OverridePort(Port) Address

	IsFqdn() bool
}
