package yuubinsya

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya/entity"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

type client struct {
	netapi.Proxy

	handshaker entity.Handshaker
}

func New(config *protocol.Protocol_Yuubinsya) protocol.WrapProxy {
	return func(dialer netapi.Proxy) (netapi.Proxy, error) {
		c := &client{
			dialer,
			NewHandshaker(config.Yuubinsya.GetEncrypted(), []byte(config.Yuubinsya.Password)),
		}

		return c, nil
	}
}

func (c *client) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	conn, err := c.Proxy.Conn(ctx, addr)
	if err != nil {
		return nil, err
	}

	hconn, err := c.handshaker.HandshakeClient(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}

	return newConn(hconn, addr, c.handshaker), nil
}

func (c *client) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	/*
		see (&yuubinsya{}).StartQUIC()
		if c.quic {
			return c.netapi.PacketConn(addr)
		}
	*/

	conn, err := c.Proxy.Conn(ctx, addr)
	if err != nil {
		return nil, err
	}

	hconn, err := c.handshaker.HandshakeClient(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return newPacketConn(hconn, c.handshaker), nil
}

type PacketConn struct {
	headerWrote bool
	remain      int

	net.Conn

	handshaker entity.Handshaker
	addr       netapi.Address

	hmux sync.Mutex
	rmux sync.Mutex
}

func newPacketConn(conn net.Conn, handshaker entity.Handshaker) net.PacketConn {
	return &PacketConn{Conn: conn, handshaker: handshaker}
}

func (c *PacketConn) WriteTo(payload []byte, addr net.Addr) (int, error) {
	taddr, err := netapi.ParseSysAddr(addr)
	if err != nil {
		return 0, fmt.Errorf("failed to parse addr: %w", err)
	}
	s5Addr := s5c.ParseAddr(taddr)

	w := pool.GetBuffer()
	defer pool.PutBuffer(w)

	if !c.headerWrote {
		c.hmux.Lock()
		if !c.headerWrote {
			c.handshaker.PacketHeader(w)
			defer func() {
				c.headerWrote = true
				c.hmux.Unlock()
			}()
		} else {
			c.hmux.Unlock()
		}
	}

	b := bytes.NewBuffer(payload)

	for b.Len() > 0 {
		data := b.Next(nat.MaxSegmentSize)
		w.Write(s5Addr)
		_ = binary.Write(w, binary.BigEndian, uint16(len(data)))
		w.Write(data)

		n, err := c.Conn.Write(w.Bytes())

		w.Reset()

		if err != nil {
			return len(payload) - b.Len() + len(data) - n, fmt.Errorf("write to %v failed: %w", addr, err)
		}
	}

	return len(payload), nil
}

func (c *PacketConn) ReadFrom(payload []byte) (n int, _ net.Addr, err error) {
	c.rmux.Lock()
	defer c.rmux.Unlock()

	if c.remain > 0 {
		readLength := len(payload)
		if c.remain < readLength {
			readLength = c.remain
		}

		n, err := c.Conn.Read(payload[:readLength])
		c.remain -= n
		return n, c.addr, err
	}

	addr, err := s5c.ResolveAddr(c.Conn)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to resolve udp packet addr: %w", err)
	}
	c.addr = addr.Address(statistic.Type_udp)

	var length uint16
	if err = binary.Read(c.Conn, binary.BigEndian, &length); err != nil {
		return 0, nil, fmt.Errorf("read length failed: %w", err)
	}

	plen := len(payload)
	if int(length) < plen {
		plen = int(length)
	} else {
		c.remain = int(length) - plen
	}

	n, err = io.ReadFull(c.Conn, payload[:plen])
	return n, c.addr, err
}

type Conn struct {
	headerWrote bool

	net.Conn

	addr       netapi.Address
	handshaker entity.Handshaker
}

func newConn(con net.Conn, addr netapi.Address, handshaker entity.Handshaker) net.Conn {
	return &Conn{
		Conn:       con,
		addr:       addr,
		handshaker: handshaker,
	}
}

func (c *Conn) Write(b []byte) (int, error) {
	if c.headerWrote {
		return c.Conn.Write(b)
	}

	c.headerWrote = true

	buf := pool.GetBuffer()
	defer pool.PutBuffer(buf)

	c.handshaker.StreamHeader(buf, c.addr)
	buf.Write(b)

	if n, err := c.Conn.Write(buf.Bytes()); err != nil {
		return n, err
	}

	return len(b), nil
}
