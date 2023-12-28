package tools

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/yerror"
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

func ParseAddr(addr netapi.Address) ADDR {
	var buf []byte
	switch addr.Type() {
	case netapi.IP:
		ip, _ := addr.AddrPort(context.TODO())
		if ip.Addr().Is4() {
			buf = make([]byte, 1+4+2)
			buf[0] = 0x01
		} else {
			buf = make([]byte, 1+16+2)
			buf[0] = 0x04
		}
		copy(buf[1:], ip.Addr().AsSlice())

	case netapi.DOMAIN:
		fallthrough
	default:
		buf = make([]byte, 1+1+len(addr.Hostname())+2)
		buf[0] = 0x03
		buf[1] = byte(len(addr.Hostname()))
		copy(buf[2:], []byte(addr.Hostname()))
	}

	binary.BigEndian.PutUint16(buf[len(buf)-2:], addr.Port().Port())

	return buf
}

func ParseAddrWriter(addr netapi.Address, buf io.Writer) {
	switch addr.Type() {
	case netapi.IP:
		if ip := yerror.Must(addr.IP(context.TODO())).To4(); ip != nil {
			_, _ = buf.Write([]byte{0x01})
			_, _ = buf.Write(ip)
		} else {
			_, _ = buf.Write([]byte{0x04})
			_, _ = buf.Write(yerror.Must(addr.IP(context.TODO())).To16())
		}
	case netapi.DOMAIN:
		fallthrough
	default:
		_, _ = buf.Write([]byte{0x03, byte(len(addr.Hostname()))})
		_, _ = buf.Write([]byte(addr.Hostname()))
	}
	_ = binary.Write(buf, binary.BigEndian, addr.Port().Port())
}

type ADDR []byte

func (a ADDR) Address(network statistic.Type) netapi.Address {
	if len(a) == 0 {
		return netapi.EmptyAddr
	}

	var hostname string
	switch a[0] {
	case IPv4, IPv6:
		hostname = net.IP(a[1 : len(a)-2]).String()
	case Domain:
		hostname = string(a[2 : len(a)-2])
	}
	port := binary.BigEndian.Uint16(a[len(a)-2:])

	return netapi.ParseAddressPort(network, hostname, netapi.ParsePort(port))
}

func ResolveAddr(r io.Reader) (ADDR, error) {
	var buf [2]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return nil, fmt.Errorf("unable to read addr type: %w", err)
	}

	var addr ADDR

	switch buf[0] {
	case IPv4:
		addr = make([]byte, 1+4+2)
	case IPv6:
		addr = make([]byte, 1+16+2)
	case Domain:
		addr = make([]byte, 1+1+buf[1]+2)
	default:
		return nil, fmt.Errorf("unknown addr type: %d", buf[0])
	}

	copy(addr[:2], buf[:])

	if _, err := io.ReadFull(r, addr[2:]); err != nil {
		return nil, err
	}

	return addr, nil
}
