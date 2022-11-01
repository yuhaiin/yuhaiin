package client

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/simple"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/utils/yerror"
)

func Dial(host, port, user, password string) proxy.Proxy {
	addr, err := proxy.ParseAddress("tcp", net.JoinHostPort(host, port))
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

func ParseAddr(hostname proxy.Address) []byte {
	buf := bytes.NewBuffer(nil)
	ParseAddrWriter(hostname, buf)
	return buf.Bytes()
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
		buf.Write([]byte{0x03})
		buf.Write([]byte{byte(len(addr.Hostname()))})
		buf.Write([]byte(addr.Hostname()))
	}

	buf.Write([]byte{byte(addr.Port().Port() >> 8), byte(addr.Port().Port() & 255)})

}

func ResolveAddr(network string, r io.Reader) (_ proxy.Address, size int, err error) {
	var byteBuf [1]byte
	if size, err = io.ReadFull(r, byteBuf[:]); err != nil {
		return nil, 0, fmt.Errorf("unable to read ATYP: %w", err)
	}

	var bufSize int
	switch byteBuf[0] {
	case IPv4:
		bufSize = 4
	case IPv6:
		bufSize = 16
	case Domain:
		length := make([]byte, 1)
		if _, err = io.ReadFull(r, length); err != nil {
			return nil, 0, fmt.Errorf("failed to read domain name length: %w", err)
		}

		size += 1

		bufSize = int(length[0])
	default:
		return nil, 0, fmt.Errorf("invalid ATYP " + strconv.FormatInt(int64(byteBuf[0]), 10))
	}

	buf := make([]byte, bufSize)
	if _, err = io.ReadFull(r, buf[:]); err != nil {
		return nil, 0, fmt.Errorf("failed to read IPv6: %w", err)
	}
	size += bufSize

	var hostname string
	switch byteBuf[0] {
	case IPv4, IPv6:
		hostname = net.IP(buf[:]).String()
	case Domain:
		hostname = string(buf)
	}

	if _, err = io.ReadFull(r, buf[:2]); err != nil {
		return nil, 0, fmt.Errorf("failed to read port: %w", err)
	}
	size += 2
	port := binary.BigEndian.Uint16(buf[0:2])

	return proxy.ParseAddressSplit(network, hostname, proxy.ParsePort(port)), size, nil
}
