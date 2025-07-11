package tun2socket

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/device"
	"gvisor.dev/gvisor/pkg/tcpip"
)

var (
	loopbackv4 = tcpip.AddrFrom4([4]byte{127, 0, 0, 1})
	loopbackv6 = tcpip.AddrFrom16([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
)

type TCP struct {
	v4listener *net.TCPListener
	v6listener *net.TCPListener
	table      *tableSplit
	portalv4   net.IP
	portalv6   net.IP
	device.InterfaceAddress
	mtu int

	ctx      context.Context
	cancel   context.CancelFunc
	connChan chan *Conn
}

func NewTCP(opt *device.Opt, v4, v6 *net.TCPListener, table *tableSplit) *TCP {
	ctx, cancel := context.WithCancel(context.Background())

	t := &TCP{
		ctx:              ctx,
		cancel:           cancel,
		connChan:         make(chan *Conn, 100),
		v4listener:       v4,
		v6listener:       v6,
		portalv4:         opt.V4Address().Addr().Next().AsSlice(),
		portalv6:         opt.V6Address().Addr().Next().AsSlice(),
		InterfaceAddress: opt.InterfaceAddress(),
		table:            table,
		mtu:              opt.MTU,
	}

	go t.loopv4()
	go t.loopv6()

	return t
}

type Conn struct {
	*net.TCPConn
	tuple Tuple
}

func (t *TCP) loopv4() {
	for t.v4listener.SetDeadline(time.Time{}) == nil {
		c, err := t.v4listener.AcceptTCP()
		if err != nil {
			log.Warn("tun2socket v4 tcp accept failed", "err", err)
			continue
		}

		addr := c.RemoteAddr().(*net.TCPAddr)

		tup := t.table.tupleOf(uint16(addr.Port), false)

		if !(t.portalv4.Equal(addr.IP) && tup != zeroTuple) {
			_ = c.Close()
			log.Warn("tun2socket v4 unknown remote addr", "addr", addr, "tuple", tup)
			continue
		}

		if tup.DestinationPort != 53 && tup.DestinationAddr.Equal(t.InterfaceAddress.Addressv4) {
			tup.DestinationAddr = loopbackv4
		}

		select {
		case <-t.ctx.Done():
			return
		case t.connChan <- &Conn{c, tup}:
		}
	}
}

func (t *TCP) loopv6() {
	for t.v6listener.SetDeadline(time.Time{}) == nil {
		c, err := t.v6listener.AcceptTCP()
		if err != nil {
			log.Warn("tun2socket v6 tcp accept failed", "err", err)
			continue
		}

		addr := c.RemoteAddr().(*net.TCPAddr)

		tup := t.table.tupleOf(uint16(addr.Port), true)

		if !(t.portalv6.Equal(addr.IP) && tup != zeroTuple) {
			_ = c.Close()
			log.Warn("tun2socket v6 unknown remote addr", "addr", addr, "tuple", tup)
			continue
		}

		if tup.DestinationPort != 53 && tup.DestinationAddr.Equal(t.InterfaceAddress.AddressV6) {
			tup.DestinationAddr = loopbackv6
		}

		select {
		case <-t.ctx.Done():
			return
		case t.connChan <- &Conn{c, tup}:
		}
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

// Accept conn
func (t *TCP) Accept() (*Conn, error) {
	select {
	case <-t.ctx.Done():
		return nil, net.ErrClosed
	case c := <-t.connChan:
		return c, nil
	}
}

func (t *TCP) Close() error {
	t.cancel()

	var er error
	if err := t.v6listener.Close(); err != nil {
		er = errors.Join(er, err)
	}

	if err := t.v4listener.Close(); err != nil {
		er = errors.Join(er, err)
	}

	for {
		select {
		case c, ok := <-t.connChan:
			if !ok {
				return er
			}

			_ = c.Close()
		default:
			return er
		}
	}
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
