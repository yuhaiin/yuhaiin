//go:build !windows
// +build !windows

package tproxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	is "github.com/Asutorufa/yuhaiin/pkg/net/interfaces/server"
	lis "github.com/Asutorufa/yuhaiin/pkg/net/proxy/server"
)

func newUDPServer(host string, dialer proxy.Proxy) (is.Server, error) {
	return lis.NewUDPServer(host,
		lis.UDPWithListenConfig(net.ListenConfig{Control: controlUDP}),
		lis.UDPWithListenFunc(func(pc net.PacketConn) error { return handleUDP(pc, dialer) }))
}

func controlUDP(network, address string, c syscall.RawConn) error {
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

func handleUDP(l net.PacketConn, p proxy.Proxy) error {
	u := l.(*net.UDPConn)

	var tempDelay time.Duration
	for {
		oob := make([]byte, 1024)
		b := make([]byte, 1024)
		n, oobn, _, addr, err := u.ReadMsgUDP(b, oob)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}

				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}

				log.Printf("tcp sever: Accept error: %v; retrying in %v\n", err, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				log.Printf("checked udp server closed: %v\n", err)
			} else {
				log.Printf("udp server accept failed: %v\n", err)
			}
			return fmt.Errorf("read msg udp failed: %w", err)
		}

		err = handleSingleUDPReq(oob[:oobn], b[:n], addr, p)
		if err != nil {
			log.Printf("handle single udp req failed: %v", err)
		}
	}
}

func handleSingleUDPReq(oob, b []byte, addr *net.UDPAddr, p proxy.Proxy) error {

	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return fmt.Errorf("parsing socket control message: %s", err)
	}

	var originalDst *net.UDPAddr
	for _, msg := range msgs {
		if msg.Header.Level == syscall.SOL_IP && msg.Header.Type == syscall.IP_RECVORIGDSTADDR {
			originalDstRaw := &syscall.RawSockaddrInet4{}
			if err = binary.Read(bytes.NewReader(msg.Data), binary.LittleEndian, originalDstRaw); err != nil {
				return fmt.Errorf("reading original destination address: %s", err)
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
				return fmt.Errorf("original destination is an unsupported network family")
			}
		}
	}

	if originalDst == nil {
		return fmt.Errorf("unable to obtain original destination: %s", err)
	}

	conn, err := p.PacketConn(originalDst.IP.String())
	if err != nil {
		return fmt.Errorf("get packet conn failed: %w", err)
	}
	defer conn.Close()

	_, err = conn.WriteTo(b, originalDst)
	if err != nil {
		return fmt.Errorf("write data to remote server failed: %w", err)
	}

	n, _, err := conn.ReadFrom(b)
	if err != nil {
		return fmt.Errorf("read data from remote server failed: %w", err)
	}

	local, err := DialUDP("udp", originalDst, addr)
	if err != nil {
		return fmt.Errorf("dial local udp failed: %w", err)
	}

	_, err = local.Write(b[:n])
	return err
}

// DialUDP connects to the remote address raddr on the network net,
// which must be "udp", "udp4", or "udp6".  If laddr is not nil, it is
// used as the local address for the connection.
func DialUDP(network string, laddr *net.UDPAddr, raddr *net.UDPAddr) (*net.UDPConn, error) {
	remoteSocketAddress, err := udpAddrToSocketAddr(raddr)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("build destination socket address: %s", err)}
	}

	localSocketAddress, err := udpAddrToSocketAddr(laddr)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("build local socket address: %s", err)}
	}

	fileDescriptor, err := syscall.Socket(udpAddrFamily(network, laddr, raddr), syscall.SOCK_DGRAM, 0)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("socket open: %s", err)}
	}

	if err = syscall.SetsockoptInt(fileDescriptor, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		syscall.Close(fileDescriptor)
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("set socket option: SO_REUSEADDR: %s", err)}
	}

	if err = syscall.SetsockoptInt(fileDescriptor, syscall.SOL_IP, syscall.IP_TRANSPARENT, 1); err != nil {
		syscall.Close(fileDescriptor)
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("set socket option: IP_TRANSPARENT: %s", err)}
	}

	if err = syscall.Bind(fileDescriptor, localSocketAddress); err != nil {
		syscall.Close(fileDescriptor)
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("socket bind: %s", err)}
	}

	if err = syscall.Connect(fileDescriptor, remoteSocketAddress); err != nil {
		syscall.Close(fileDescriptor)
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("socket connect: %s", err)}
	}

	fdFile := os.NewFile(uintptr(fileDescriptor), fmt.Sprintf("net-udp-dial-%s", raddr.String()))
	defer fdFile.Close()

	remoteConn, err := net.FileConn(fdFile)
	if err != nil {
		syscall.Close(fileDescriptor)
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("convert file descriptor to connection: %s", err)}
	}

	return remoteConn.(*net.UDPConn), nil
}

// udpAddToSockerAddr will convert a UDPAddr
// into a Sockaddr that may be used when
// connecting and binding sockets
func udpAddrToSocketAddr(addr *net.UDPAddr) (syscall.Sockaddr, error) {
	switch {
	case addr.IP.To4() != nil:
		ip := [4]byte{}
		copy(ip[:], addr.IP.To4())

		return &syscall.SockaddrInet4{Addr: ip, Port: addr.Port}, nil

	default:
		ip := [16]byte{}
		copy(ip[:], addr.IP.To16())

		zoneID, err := strconv.ParseUint(addr.Zone, 10, 32)
		if err != nil {
			return nil, err
		}

		return &syscall.SockaddrInet6{Addr: ip, Port: addr.Port, ZoneId: uint32(zoneID)}, nil
	}
}

// udpAddrFamily will attempt to work
// out the address family based on the
// network and UDP addresses
func udpAddrFamily(net string, laddr, raddr *net.UDPAddr) int {
	switch net[len(net)-1] {
	case '4':
		return syscall.AF_INET
	case '6':
		return syscall.AF_INET6
	}

	if (laddr == nil || laddr.IP.To4() != nil) &&
		(raddr == nil || laddr.IP.To4() != nil) {
		return syscall.AF_INET
	}
	return syscall.AF_INET6
}
