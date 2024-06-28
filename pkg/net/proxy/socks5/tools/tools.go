package tools

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

const (
	NoAuthenticationRequired = 0x00
	Gssapi                   = 0x01
	UserAndPassword          = 0x02
	NoAcceptableMethods      = 0xff

	Succeeded                     = 0x00
	SocksServerFailure            = 0x01
	ConnectionNotAllowedByRuleset = 0x02
	NetworkUnreachable            = 0x03
	HostUnreachable               = 0x04
	ConnectionRefused             = 0x05
	TTLExpired                    = 0x06
	CommandNotSupport             = 0x07
	AddressTypeNotSupport         = 0x08
)

type CMD byte

const (
	Connect CMD = 0x01
	Bind    CMD = 0x02
	Udp     CMD = 0x03

	IPv4   byte = 0x01
	Domain byte = 0x03
	IPv6   byte = 0x04
)

func EncodeAddr(addr netapi.Address, buf io.Writer) {
	if addr.IsFqdn() {
		_, _ = buf.Write([]byte{0x03, byte(len(addr.Hostname()))})
		_, _ = buf.Write([]byte(addr.Hostname()))
	} else {
		if ip := addr.(netapi.IPAddress).IP().To4(); ip != nil {
			_, _ = buf.Write([]byte{0x01})
			_, _ = buf.Write(ip)
		} else {
			_, _ = buf.Write([]byte{0x04})
			_, _ = buf.Write(addr.(netapi.IPAddress).IP().To16())
		}
	}
	_ = binary.Write(buf, binary.BigEndian, addr.Port())
}

type Addr []byte

func (a Addr) Address(network string) netapi.Address {
	if len(a) == 0 {
		return netapi.EmptyAddr
	}

	port := binary.BigEndian.Uint16(a[len(a)-2:])

	switch a[0] {
	case IPv4, IPv6:
		ip := make(net.IP, len(a[1:len(a)-2]))
		copy(ip, a[1:len(a)-2])
		return netapi.ParseIPAddrPort(network, ip, port)
	case Domain:
		hostname := string(a[2 : len(a)-2])
		return netapi.ParseDomainPort(network, hostname, port)
	}

	return netapi.EmptyAddr
}

func ResolveAddr(r io.Reader) (Addr, error) {
	var buf [2]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return nil, fmt.Errorf("unable to read addr type: %w", err)
	}

	addr := pool.GetBytes(1 + 255 + 2 + 1)

	switch buf[0] {
	case IPv4:
		addr = addr[:1+4+2]
	case IPv6:
		addr = addr[:1+16+2]
	case Domain:
		addr = addr[:int(1+1+buf[1]+2)]
	default:
		return nil, fmt.Errorf("unknown addr type: %d", buf[0])
	}

	copy(addr[:2], buf[:])

	if _, err := io.ReadFull(r, addr[2:]); err != nil {
		return nil, err
	}

	return addr, nil
}

func ParseAddr(addr netapi.Address) Addr {
	buf := pool.NewBufferSize(1 + 255 + 2 + 1)
	EncodeAddr(addr, buf)
	return buf.Bytes()
}
