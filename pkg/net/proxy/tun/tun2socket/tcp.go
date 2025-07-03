package tun2socket

import (
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/device"
	"gvisor.dev/gvisor/pkg/tcpip"
)

var (
	loopback   = tcpip.AddrFrom4([4]byte{127, 0, 0, 1})
	loopbackv6 = tcpip.AddrFrom16([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
)

type TCP struct {
	listener *net.TCPListener
	table    *tableSplit
	portal   net.IP
	portalv6 net.IP
	device.InterfaceAddress
}

type Conn struct {
	*net.TCPConn
	tuple Tuple
}

func (t *TCP) Accept() (*Conn, error) {
	c, err := t.listener.AcceptTCP()
	if err != nil {
		return nil, err
	}

	addr := c.RemoteAddr().(*net.TCPAddr)

	v6 := addr.IP.To4() == nil

	var portal net.IP
	if v6 {
		portal = t.portalv6
	} else {
		portal = t.portal
	}

	tup := t.table.tupleOf(uint16(addr.Port), v6)

	if !(portal.Equal(addr.IP) && tup != zeroTuple) {
		_ = c.Close()
		return nil, net.InvalidAddrError("unknown remote addr")
	}

	if tup.DestinationPort != 53 {
		if tup.DestinationAddr.Len() == 4 && tup.DestinationAddr.Equal(t.InterfaceAddress.Address) {
			tup.DestinationAddr = loopback
		} else if tup.DestinationAddr.Equal(t.InterfaceAddress.AddressV6) {
			tup.DestinationAddr = loopbackv6
		}
	}

	/*
			sys, err := c.SyscallConn()
			if err == nil {
				_ = sys.Control(func(fd uintptr) {
					setSocketOptions(fd)
				})
			}

			https://www.kernel.org/doc/Documentation/networking/udplite.txt
		  	3) Disabling the Checksum Computation
		  	On both sender and receiver, checksumming will always be performed
		  	and cannot be disabled using SO_NO_CHECK. Thus
		        setsockopt(sockfd, SOL_SOCKET, SO_NO_CHECK,  ... );
		  	will always will be ignored, while the value of
		        getsockopt(sockfd, SOL_SOCKET, SO_NO_CHECK, &value, ...);
		  	is meaningless (as in TCP). Packets with a zero checksum field are
		  	illegal (cf. RFC 3828, sec. 3.1) and will be silently discarded.
	*/

	return &Conn{
		TCPConn: c,
		tuple:   tup,
	}, nil
}

func (t *TCP) Close() error {
	return t.listener.Close()
}

func (t *TCP) Addr() net.Addr {
	return t.listener.Addr()
}

func (t *TCP) SetDeadline(time time.Time) error {
	return t.listener.SetDeadline(time)
}

func (c *Conn) Close() error {
	return c.TCPConn.Close()
}

func (c *Conn) LocalAddr() net.Addr {
	src := c.tuple.SourceAddr
	return &net.TCPAddr{
		IP:   src.AsSlice(),
		Port: int(c.tuple.SourcePort),
	}
}

func (c *Conn) RemoteAddr() net.Addr {
	dst := c.tuple.DestinationAddr
	return &net.TCPAddr{
		IP:   dst.AsSlice(),
		Port: int(c.tuple.DestinationPort),
	}
}

func (c *Conn) RawConn() (net.Conn, bool) { return c.TCPConn, true }
