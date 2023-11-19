package tproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"
	"unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	cl "github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"golang.org/x/sys/unix"
)

func controlUDP(c syscall.RawConn) error {
	var fn = func(s uintptr) {
		err := syscall.SetsockoptInt(int(s), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
		if err != nil {
			log.Error("set socket with SOL_IP, IP_TRANSPARENT failed", "err", err)
		}

		val, err := syscall.GetsockoptInt(int(s), syscall.SOL_IP, syscall.IP_TRANSPARENT)
		if err != nil {
			log.Error("get socket with SOL_IP, IP_TRANSPARENT failed", "err", err)
		} else {
			log.Error("value of IP_TRANSPARENT option", "val", val)
		}

		err = syscall.SetsockoptInt(int(s), syscall.SOL_IP, syscall.IP_RECVORIGDSTADDR, 1)
		if err != nil {
			log.Error("set socket with SOL_IP, IP_RECVORIGDSTADDR failed", "err", err)
		}

		val, err = syscall.GetsockoptInt(int(s), syscall.SOL_IP, syscall.IP_RECVORIGDSTADDR)
		if err != nil {
			log.Error("get socket with SOL_IP, IP_RECVORIGDSTADDR failed", "err", err)
		} else {
			log.Error("value of IP_RECVORIGDSTADDR option", "val", val)
		}
	}

	if err := c.Control(fn); err != nil {
		return err
	}

	return nil
}

// DialUDP connects to the remote address raddr on the network net,
// which must be "udp", "udp4", or "udp6".  If laddr is not nil, it is
// used as the local address for the connection.
func DialUDP(network string, laddr *net.UDPAddr, raddr *net.UDPAddr) (*net.UDPConn, error) {
	remoteSocketAddress, err := udpAddrToSocketAddr(raddr)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("build destination socket address: %w", err)}
	}

	localSocketAddress, err := udpAddrToSocketAddr(laddr)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("build local socket address: %w", err)}
	}

	fileDescriptor, err := syscall.Socket(udpAddrFamily(network, laddr, raddr), syscall.SOCK_DGRAM, 0)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("socket open: %w", err)}
	}

	if err = syscall.SetsockoptInt(fileDescriptor, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		syscall.Close(fileDescriptor)
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("set socket option: SO_REUSEADDR: %w", err)}
	}

	if err = syscall.SetsockoptInt(fileDescriptor, syscall.SOL_IP, syscall.IP_TRANSPARENT, 1); err != nil {
		syscall.Close(fileDescriptor)
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("set socket option: IP_TRANSPARENT: %w", err)}
	}

	if err = syscall.Bind(fileDescriptor, localSocketAddress); err != nil {
		syscall.Close(fileDescriptor)
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("socket bind: %w", err)}
	}

	if err = syscall.Connect(fileDescriptor, remoteSocketAddress); err != nil {
		syscall.Close(fileDescriptor)
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("socket connect: %w", err)}
	}

	fdFile := os.NewFile(uintptr(fileDescriptor), fmt.Sprintf("net-udp-dial-%s", raddr.String()))
	defer fdFile.Close()

	remoteConn, err := net.FileConn(fdFile)
	if err != nil {
		syscall.Close(fileDescriptor)
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("convert file descriptor to connection: %w", err)}
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

		var zoneID uint64
		if addr.Zone != "" {
			var err error
			zoneID, err = strconv.ParseUint(addr.Zone, 10, 32)
			if err != nil {
				return nil, err
			}
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
		(raddr == nil || raddr.IP.To4() != nil) {
		return syscall.AF_INET
	}
	return syscall.AF_INET6
}

//credit: https://github.com/LiamHaworth/go-tproxy/blob/master/tproxy_udp.go ,  which is under MIT License

// ListenUDP will construct a new UDP listener
// socket with the Linux IP_TRANSPARENT option
// set on the underlying socket
func ListenUDP(network string, laddr *net.UDPAddr) (*net.UDPConn, error) {
	listener, err := net.ListenUDP(network, laddr)
	if err != nil {
		return nil, err
	}

	fileDescriptorSource, err := listener.File()
	if err != nil {
		return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: laddr, Err: fmt.Errorf("get file descriptor: %s", err)}
	}
	defer fileDescriptorSource.Close()

	fileDescriptor := int(fileDescriptorSource.Fd())
	if err = syscall.SetsockoptInt(fileDescriptor, syscall.SOL_IP, syscall.IP_TRANSPARENT, 1); err != nil {
		return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: laddr, Err: fmt.Errorf("set socket option: IP_TRANSPARENT: %s", err)}
	}

	if err = syscall.SetsockoptInt(fileDescriptor, syscall.SOL_IP, syscall.IP_RECVORIGDSTADDR, 1); err != nil {
		return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: laddr, Err: fmt.Errorf("set socket option: IP_RECVORIGDSTADDR: %s", err)}
	}

	return listener, nil
}

var errContinue = errors.New("continue")

// ReadFromUDP reads a UDP packet from c, copying the payload into b.
// It returns the number of bytes copied into b and the return address
// that was on the packet.
//
// Out-of-band data is also read in so that the original destination
// address can be identified and parsed.
func ReadFromUDP(conn *net.UDPConn, b []byte) (n int, srcAddr *net.UDPAddr, dstAddr *net.UDPAddr, err error) {
	oob := make([]byte, 1024)
	var oobn int
	n, oobn, _, srcAddr, err = conn.ReadMsgUDP(b, oob)
	if err != nil {
		return
	}

	msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		err = fmt.Errorf("%w parsing socket control message: %s", errContinue, err)
		return
	}

	//from golang.org/x/sys/unix/sockcmsg_linux.go ParseOrigDstAddr

	for _, m := range msgs {

		switch {
		case m.Header.Level == syscall.SOL_IP && m.Header.Type == syscall.IP_ORIGDSTADDR:
			pp := (*syscall.RawSockaddrInet4)(unsafe.Pointer(&m.Data[0]))

			p := (*[2]byte)(unsafe.Pointer(&pp.Port))

			dstAddr = &net.UDPAddr{
				IP:   net.IPv4(pp.Addr[0], pp.Addr[1], pp.Addr[2], pp.Addr[3]),
				Port: int(p[0])<<8 + int(p[1]),
			}

		case m.Header.Level == syscall.SOL_IPV6 && m.Header.Type == unix.IPV6_ORIGDSTADDR:
			pp := (*syscall.RawSockaddrInet6)(unsafe.Pointer(&m.Data[0]))
			p := (*[2]byte)(unsafe.Pointer(&pp.Port))
			dstAddr = &net.UDPAddr{
				IP:   net.IP(pp.Addr[:]),
				Port: int(p[0])<<8 + int(p[1]),
				Zone: strconv.Itoa(int(pp.Scope_id)),
			}

		}

	}

	if dstAddr == nil {
		err = fmt.Errorf("%w unable to obtain original destination: %v (src: %v)", errContinue, err, srcAddr)
		return
	}

	return
}

type udpserver struct {
	lis net.PacketConn
}

func (u *udpserver) Close() error {
	return u.lis.Close()
}

func isHandleDNS(port uint16) bool {
	return port == 53
}

func newUDP(opt *cl.Opts[*cl.Protocol_Tproxy]) (*udpserver, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", opt.Protocol.Tproxy.GetHost())
	if err != nil {
		return nil, err
	}
	lis, err := dialer.ListenPacketWithOptions("udp", udpAddr.String(), &dialer.Options{
		MarkSymbol: func(socket int32) bool {
			return dialer.LinuxMarkSymbol(socket, 0xff) == nil
		},
	})
	if err != nil {
		return nil, err
	}

	udpLis, ok := lis.(*net.UDPConn)
	if !ok {
		lis.Close()
		return nil, fmt.Errorf("listen is not udplistener")
	}

	sysConn, err := udpLis.SyscallConn()
	if err != nil {
		lis.Close()
		return nil, err
	}

	err = controlUDP(sysConn)
	if err != nil {
		lis.Close()
		return nil, err
	}

	log.Info("new tproxy udp server", "host", lis.LocalAddr())

	s := &udpserver{lis: lis}

	go func() {
		for {
			buf := pool.GetBytesV2(nat.MaxSegmentSize)
			n, src, dst, err := ReadFromUDP(udpLis, buf.Bytes())
			if err != nil {
				pool.PutBytesV2(buf)
				log.Error("start udp server failed", "err", err)
				if !errors.Is(err, errContinue) {
					break
				}
				continue
			}

			buf.ResetSize(0, n)

			if isHandleDNS(uint16(dst.Port)) && opt.Protocol.Tproxy.GetDnsHijacking() {
				go func() {
					ctx := context.TODO()
					if opt.Protocol.Tproxy.GetForceFakeip() {
						ctx = context.WithValue(ctx, netapi.ForceFakeIP{}, true)
					}

					err := opt.DNSHandler.Do(ctx, buf, func(b []byte) error {
						back, err := DialUDP("udp", dst, src)
						if err != nil {
							return fmt.Errorf("udp server dial failed: %w", err)
						}
						defer back.Close()
						_, err = back.Write(b)
						return err
					})
					if err != nil {
						log.Error("udp server handle DnsHijacking failed", "err", err)
					}
				}()
				continue
			}

			dstAddr, _ := netapi.ParseSysAddr(dst)
			opt.Handler.Packet(context.TODO(), &netapi.Packet{
				Src:     src,
				Dst:     dstAddr,
				Payload: buf,
				WriteBack: func(b []byte, addr net.Addr) (int, error) {
					defer pool.PutBytesV2(buf)

					ad, err := netapi.ParseSysAddr(addr)
					if err != nil {
						return 0, err
					}

					uaddr, err := ad.UDPAddr(context.Background())
					if err != nil {
						return 0, err
					}

					back, err := DialUDP("udp", uaddr, src)
					if err != nil {
						return 0, fmt.Errorf("udp server dial failed: %w", err)
					}
					defer back.Close()

					n, err := back.Write(b)
					if err != nil {
						return 0, err
					}

					return n, nil
				},
			})
		}
	}()

	return s, nil
}
