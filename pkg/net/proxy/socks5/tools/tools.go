package tools

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"unsafe"

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

	// MaxAddrLength  domainMaxLen + 0x03 + domainLen + portLen
	MaxAddrLength = 255 + 1 + 1 + 2
)

func WriteAddr(addr netapi.Address, buf io.Writer) {
	if addr.IsFqdn() {
		hostname := addr.Hostname()
		_, _ = buf.Write([]byte{0x03, byte(len(hostname))})
		_, _ = buf.Write(unsafe.Slice(unsafe.StringData(hostname), len(hostname)))
	} else {
		if ip := addr.(netapi.IPAddress).IP(); ip.To4() != nil {
			_, _ = buf.Write([]byte{0x01})
			_, _ = buf.Write(ip.To4())
		} else {
			_, _ = buf.Write([]byte{0x04})
			_, _ = buf.Write(ip.To16())
		}
	}

	_ = pool.BinaryWriteUint16(buf, binary.BigEndian, addr.Port())
}

func EncodeAddr(addr netapi.Address, buf []byte) int {
	var offset int
	if addr.IsFqdn() {
		hostname := addr.Hostname()
		buf[0] = 0x03
		hlen := copy(buf[2:], hostname)
		buf[1] = byte(hlen)
		offset = 2 + hlen
	} else {
		if ip := addr.(netapi.IPAddress).IP(); ip.To4() != nil {
			buf[0] = 0x01
			offset = 1 + copy(buf[1:], ip.To4())
		} else {
			buf[0] = 0x04
			offset = 1 + copy(buf[1:], ip.To16())
		}
	}

	binary.BigEndian.PutUint16(buf[offset:], uint16(addr.Port()))

	return offset + 2
}

type Addr []byte

func (a Addr) Address(network string) netapi.Address {
	if len(a) == 0 {
		return netapi.EmptyAddr
	}

	port := binary.BigEndian.Uint16(a[len(a)-2:])

	switch a[0] {
	case IPv4, IPv6:
		return netapi.ParseIPAddr(network, net.IP(a[1:len(a)-2]), port)
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

	addr := pool.GetBytes(MaxAddrLength)

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

func DecodeAddr(network string, b []byte) (int, netapi.Address, error) {
	if len(b) < 3 {
		return 0, nil, io.ErrUnexpectedEOF
	}

	switch b[0] {
	case IPv4:
		return 1 + 4 + 2, netapi.ParseIPAddr(network, net.IP(b[1:5]), binary.BigEndian.Uint16(b[5:7])), nil
	case IPv6:
		return 1 + 16 + 2, netapi.ParseIPAddr(network, net.IP(b[1:17]), binary.BigEndian.Uint16(b[17:19])), nil
	case Domain:
		if len(b) < 2+int(b[1])+2 {
			return 0, nil, io.ErrUnexpectedEOF
		}
		return 1 + 1 + int(b[1]) + 2, netapi.ParseDomainPort(network, string(b[2:2+int(b[1])]), binary.BigEndian.Uint16(b[1+1+int(b[1]):])), nil
	default:
		return 0, nil, fmt.Errorf("unknown addr type: %d", b[0])
	}
}

func ReadAddr(network string, br *bufio.Reader) (int, netapi.Address, error) {
	atype, err := br.ReadByte()
	if err != nil {
		return 0, nil, err
	}

	switch atype {
	case IPv4, IPv6:
		var ipLen int
		if atype == IPv4 {
			ipLen = 4
		} else {
			ipLen = 16
		}

		ip, err := br.Peek(ipLen + 2)
		if err != nil {
			return 0, nil, err
		}

		port := binary.BigEndian.Uint16(ip[ipLen:])
		addr := netapi.ParseIPAddr(network, net.IP(ip[:ipLen]), port)

		_, err = br.Discard(ipLen + 2)
		if err != nil {
			return 0, nil, err
		}

		return 1 + ipLen + 2, addr, nil

	case Domain:
		domainLen, err := br.ReadByte()
		if err != nil {
			return 0, nil, err
		}

		domainBytes, err := br.Peek(int(domainLen) + 2)
		if err != nil {
			return 0, nil, err
		}

		domain := string(domainBytes[:domainLen])
		port := binary.BigEndian.Uint16(domainBytes[domainLen:])

		_, err = br.Discard(int(domainLen) + 2)
		if err != nil {
			return 0, nil, err
		}

		return 1 + 1 + int(domainLen) + 2, netapi.ParseDomainPort(network, domain, port), nil
	}

	return 0, nil, fmt.Errorf("unknown addr type: %d", atype)
}

func ParseAddr(addr netapi.Address) Addr {
	buf := pool.NewBufferSize(1 + 255 + 2 + 1)
	WriteAddr(addr, buf)
	return buf.Bytes()
}
