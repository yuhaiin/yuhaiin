package proxy

import (
	"context"
	"net"
	"net/netip"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
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

type Port interface {
	Port() uint16
	String() string
}

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
