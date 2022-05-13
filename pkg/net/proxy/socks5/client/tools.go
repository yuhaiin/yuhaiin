package client

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/simple"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
)

func Dial(host, port, user, password string) proxy.Proxy {
	addr, err := proxy.ParseAddress("tcp", net.JoinHostPort(host, port))
	if err != nil {
		return proxy.NewErrProxy(err)
	}
	p, _ := NewSocks5(&node.PointProtocol_Socks5{Socks5: &node.Socks5{User: user, Password: password}})(
		simple.NewSimple(addr, nil))
	return p
}

func ParseAddr(hostname proxy.Address) (data []byte) {
	sendData := utils.GetBuffer()
	defer utils.PutBuffer(sendData)

	ParseAddrWriter(hostname, sendData)
	return sendData.Bytes()
}

func ParseAddrWriter(addr proxy.Address, sendData io.Writer) {
	switch addr.Type() {
	case proxy.IP:
		if ip := addr.IP().To4(); ip != nil {
			sendData.Write([]byte{0x01})
			sendData.Write(ip)
		} else {
			sendData.Write([]byte{0x04})
			sendData.Write(addr.IP().To16())
		}
	case proxy.DOMAIN:
		fallthrough
	default:
		sendData.Write([]byte{0x03})
		sendData.Write([]byte{byte(len(addr.Hostname()))})
		sendData.Write([]byte(addr.Hostname()))
	}

	sendData.Write([]byte{byte(addr.Port().Port() >> 8), byte(addr.Port().Port() & 255)})

}

func ResolveAddr(r io.Reader) (_ proxy.Address, size int, err error) {
	var byteBuf [1]byte
	if size, err = io.ReadFull(r, byteBuf[:]); err != nil {
		return nil, 0, fmt.Errorf("unable to read ATYP: %w", err)
	}

	var bufSize int

	switch byteBuf[0] {
	case ipv4:
		bufSize = 4
	case ipv6:
		bufSize = 16
	case domainName:
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
	case ipv4, ipv6:
		hostname = net.IP(buf[:]).String()
	case domainName:
		hostname = string(buf)
		size += 1
	}

	if _, err = io.ReadFull(r, buf[:2]); err != nil {
		return nil, 0, fmt.Errorf("failed to read port: %w", err)
	}
	size += 2
	port := binary.BigEndian.Uint16(buf[0:2])

	return proxy.ParseAddressSplit("", hostname, port), size, nil
}
