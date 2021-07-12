package tproxy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strconv"
	"syscall"
	"unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
)

func control() func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var fn = func(s uintptr) {
			err := syscall.SetsockoptInt(int(s), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
			if err != nil {
				log.Printf("set socket with SOL_IP, IP_TRANSPARENT failed: %v", err)
			}

			val, err := syscall.GetsockoptInt(int(s), syscall.SOL_IP, syscall.IP_TRANSPARENT)
			if err != nil {
				log.Printf("get socket with SOL_IP, IP_TRANSPARENT failed: %v", err)
			} else {
				log.Printf("value of IP_TRANSPARENT option is: %d", int(val))
			}

			err = syscall.SetsockoptInt(int(s), syscall.SOL_IP, syscall.IP_RECVORIGDSTADDR, 1)
			if err != nil {
				log.Printf("set socket with SOL_IP, IP_RECVORIGDSTADDR failed: %v", err)
			}

			val, err = syscall.GetsockoptInt(int(s), syscall.SOL_IP, syscall.IP_RECVORIGDSTADDR)
			if err != nil {
				log.Printf("get socket with SOL_IP, IP_RECVORIGDSTADDR failed: %v", err)
			} else {
				log.Printf("value of IP_RECVORIGDSTADDR option is: %d", int(val))
			}
		}

		if err := c.Control(fn); err != nil {
			return err
		}

		return nil
	}
}

func handle(b []byte, p proxy.Proxy) ([]byte, error) {
	msgs, err := syscall.ParseSocketControlMessage(b)
	if err != nil {
		return nil, fmt.Errorf("parse socket control message failed: %w", err)
	}

	var originalDst *net.UDPAddr
	for _, msg := range msgs {
		if msg.Header.Level == syscall.SOL_IP && msg.Header.Type == syscall.IP_RECVORIGDSTADDR {
			originalDstRaw := &syscall.RawSockaddrInet4{}
			if err = binary.Read(bytes.NewReader(msg.Data), binary.LittleEndian, originalDstRaw); err != nil {
				return nil, fmt.Errorf("reading original destination address: %s", err)
			}

			switch originalDstRaw.Family {
			case syscall.AF_INET:
				pp := (*syscall.RawSockaddrInet4)(unsafe.Pointer(originalDstRaw))
				p := (*[2]byte)(unsafe.Pointer(&pp.Port))
				originalDst = &net.UDPAddr{
					IP:   net.IPv4(pp.Addr[0], pp.Addr[1], pp.Addr[2], pp.Addr[3]),
					Port: int(p[0])<<8 + int(p[1]),
				}

			case syscall.AF_INET6:
				pp := (*syscall.RawSockaddrInet6)(unsafe.Pointer(originalDstRaw))
				p := (*[2]byte)(unsafe.Pointer(&pp.Port))
				originalDst = &net.UDPAddr{
					IP:   net.IP(pp.Addr[:]),
					Port: int(p[0])<<8 + int(p[1]),
					Zone: strconv.Itoa(int(pp.Scope_id)),
				}

			default:
				return nil, fmt.Errorf("original destination is an unsupported network family")
			}
		}
	}

	conn, err := p.PacketConn(originalDst.IP.String())
	if err != nil {
		return nil, fmt.Errorf("get packet conn failed: %w", err)
	}
	defer conn.Close()

	fmt.Println("UDP write", conn.LocalAddr(), "->", originalDst)
	_, err = conn.WriteTo(b, originalDst)
	if err != nil {
		return nil, fmt.Errorf("write data to remote packetConn failed: %v", err)
	}

	respBuff := *utils.BuffPool.Get().(*[]byte)
	defer utils.BuffPool.Put(&(respBuff))

	n, addr, err := conn.ReadFrom(respBuff)
	if err != nil {
		return nil, fmt.Errorf("read data From remote packetConn failed: %v", err)
	}
	fmt.Println("UDP read from", addr.String())
	return respBuff[:n], nil
}

func NewServer(host, username, password string) (proxy.Server, error) {
	return proxy.NewUDPServer(host, handle, proxy.WithListenConfig(net.ListenConfig{Control: control()}))
}
