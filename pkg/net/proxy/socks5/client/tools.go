package client

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/simple"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/yerror"
)

func Dial(host, port, user, password string) proxy.Proxy {
	addr, err := proxy.ParseAddress(statistic.Type_tcp, net.JoinHostPort(host, port))
	if err != nil {
		return proxy.NewErrProxy(err)
	}
	p, _ := New(&protocol.Protocol_Socks5{
		Socks5: &protocol.Socks5{
			Hostname: host,
			User:     user,
			Password: password,
		}})(yerror.Must(simple.New(&protocol.Protocol_Simple{
		Simple: &protocol.Simple{
			Host:             addr.Hostname(),
			Port:             int32(addr.Port().Port()),
			PacketConnDirect: true,
		},
	})(nil)))
	return p
}

func ParseAddr(addr proxy.Address) ADDR {
	var buf []byte
	switch addr.Type() {
	case proxy.IP:
		ip, _ := addr.AddrPort()
		if ip.Addr().Is4() {
			buf = make([]byte, 1+4+2)
			buf[0] = 0x01
		} else {
			buf = make([]byte, 1+16+2)
			buf[0] = 0x04
		}
		copy(buf[1:], ip.Addr().AsSlice())

	case proxy.DOMAIN:
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

func ParseAddrWriter(addr proxy.Address, buf io.Writer) {
	switch addr.Type() {
	case proxy.IP:
		if ip := yerror.Must(addr.IP()).To4(); ip != nil {
			buf.Write([]byte{0x01})
			buf.Write(ip)
		} else {
			buf.Write([]byte{0x04})
			buf.Write(yerror.Must(addr.IP()).To16())
		}
	case proxy.DOMAIN:
		fallthrough
	default:
		buf.Write([]byte{0x03, byte(len(addr.Hostname()))})
		buf.Write([]byte(addr.Hostname()))
	}
	binary.Write(buf, binary.BigEndian, addr.Port().Port())
}

type ADDR []byte

func (a ADDR) Address(network statistic.Type) proxy.Address {
	if len(a) == 0 {
		return proxy.EmptyAddr
	}

	var hostname string
	switch a[0] {
	case IPv4, IPv6:
		hostname = net.IP(a[1 : len(a)-2]).String()
	case Domain:
		hostname = string(a[2 : len(a)-2])
	}
	port := binary.BigEndian.Uint16(a[len(a)-2:])

	return proxy.ParseAddressPort(network, hostname, proxy.ParsePort(port))
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
