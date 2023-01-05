package nat

import (
	"net"
	"net/netip"
	"time"
)

type TCP struct {
	listener *net.TCPListener
	portal   netip.Addr
	table    *table
}

type Conn struct {
	net.Conn

	tuple tuple
}

func (t *TCP) Accept() (net.Conn, error) {
	c, err := t.listener.AcceptTCP()
	if err != nil {
		return nil, err
	}

	addr := c.RemoteAddr().(*net.TCPAddr).AddrPort()

	tup := t.table.tupleOf(uint16(addr.Port()))
	if addr.Addr() != t.portal || tup == zeroTuple {
		_ = c.Close()

		return nil, net.InvalidAddrError("unknown remote addr")
	}

	_ = c.SetKeepAlive(false)

	sys, err := c.SyscallConn()
	if err == nil {
		_ = sys.Control(func(fd uintptr) {
			setSocketOptions(fd)
		})
	}

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
	return net.TCPAddrFromAddrPort(c.tuple.SourceAddr)
}

func (c *Conn) RemoteAddr() net.Addr {
	return net.TCPAddrFromAddrPort(c.tuple.DestinationAddr)
}

func (c *Conn) RawConn() (net.Conn, bool) {
	return c.Conn, true
}
