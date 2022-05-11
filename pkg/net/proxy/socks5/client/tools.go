package client

import (
	"encoding/binary"
	"errors"
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
		simple.NewSimple(addr))
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

func ResolveAddr(raw []byte) (dst string, port, size int, err error) {
	if len(raw) <= 0 {
		return "", 0, 0, fmt.Errorf("raw byte array is empty")
	}
	targetAddrRawSize := 1
	switch raw[0] {
	case ipv4:
		dst = net.IP(raw[targetAddrRawSize : targetAddrRawSize+4]).String()
		targetAddrRawSize += 4
	case ipv6:
		if len(raw) < 1+16+2 {
			return "", 0, 0, errors.New("errShortAddrRaw")
		}
		dst = net.IP(raw[1 : 1+16]).String()
		targetAddrRawSize += 16
	case domainName:
		addrLen := int(raw[1])
		if len(raw) < 1+1+addrLen+2 {
			// errShortAddrRaw
			return "", 0, 0, errors.New("error short address raw")
		}
		dst = string(raw[1+1 : 1+1+addrLen])
		targetAddrRawSize += 1 + addrLen
	default:
		// errUnrecognizedAddrType
		return "", 0, 0, errors.New("udp socks: Failed to get UDP package header")
	}
	port = (int(raw[targetAddrRawSize]) << 8) | int(raw[targetAddrRawSize+1])
	targetAddrRawSize += 2
	return dst, port, targetAddrRawSize, nil
}

func ResolveAddrReader(r io.Reader) (hostname string, port, size int, err error) {
	byteBuf := [1]byte{}
	_, err = io.ReadFull(r, byteBuf[:])
	if err != nil {
		err = fmt.Errorf("unable to read ATYP: %w", err)
		return
	}
	switch byteBuf[0] {
	case ipv4:
		var buf [6]byte
		_, err = io.ReadFull(r, buf[:])
		if err != nil {
			err = fmt.Errorf("failed to read IPv4: %w", err)
			return
		}
		hostname = net.IP(buf[0:4]).String()
		port = int(binary.BigEndian.Uint16(buf[4:6]))
	case ipv6:
		var buf [18]byte
		_, err = io.ReadFull(r, buf[:])
		if err != nil {
			err = fmt.Errorf("failed to read IPv6: %w", err)
			return
		}
		hostname = net.IP(buf[0:16]).String()
		port = int(binary.BigEndian.Uint16(buf[16:18]))
	case domainName:
		_, err = io.ReadFull(r, byteBuf[:])
		length := byteBuf[0]
		if err != nil {
			err = fmt.Errorf("failed to read domain name length")
			return
		}
		buf := make([]byte, length+2)
		_, err = io.ReadFull(r, buf)
		if err != nil {
			err = fmt.Errorf("failed to read domain name")
			return
		}
		// the fucking browser uses IP as a domain name sometimes
		host := buf[0:length]
		hostname = string(host)
		port = int(binary.BigEndian.Uint16(buf[length : length+2]))
	default:
		err = fmt.Errorf("invalid ATYP " + strconv.FormatInt(int64(byteBuf[0]), 10))
		return
	}
	return
}
