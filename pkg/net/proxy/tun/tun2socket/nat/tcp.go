package nat

import (
	"net"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
)

type TCP struct {
	listener  *net.TCPListener
	address   tcpip.Address
	addressV6 tcpip.Address
	portal    net.IP
	table     *table
}

type Conn struct {
	net.Conn

	tuple Tuple
}

func (t *TCP) Accept() (net.Conn, error) {
	c, err := t.listener.AcceptTCP()
	if err != nil {
		return nil, err
	}

	addr := c.RemoteAddr().(*net.TCPAddr)

	tup := t.table.tupleOf(uint16(addr.Port))
	if !t.portal.Equal(addr.IP) || tup == zeroTuple {
		_ = c.Close()

		return nil, net.InvalidAddrError("unknown remote addr")
	}

	if tup.DestinationAddr.Len() == 4 {
		if tup.DestinationAddr.Equal(t.address) {
			tup.DestinationAddr = tcpip.AddrFrom4([4]byte{127, 0, 0, 1})
		}
	} else {
		if tup.DestinationAddr.Equal(t.addressV6) {
			tup.DestinationAddr = tcpip.AddrFrom16([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
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
		Conn:  c,
		tuple: tup,
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

func (c *Conn) LocalAddr() net.Addr {
	return &net.TCPAddr{
		IP:   net.IP(c.tuple.SourceAddr.AsSlice()),
		Port: int(c.tuple.SourcePort),
	}
}

func (c *Conn) RemoteAddr() net.Addr {
	return &net.TCPAddr{
		IP:   net.IP(c.tuple.DestinationAddr.AsSlice()),
		Port: int(c.tuple.DestinationPort),
	}
}

func (c *Conn) RawConn() (net.Conn, bool) { return c.Conn, true }
