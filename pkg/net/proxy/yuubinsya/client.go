package yuubinsya

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/tools"
	websocket "github.com/Asutorufa/yuhaiin/pkg/net/proxy/websocket/x"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya/types"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

type client struct {
	netapi.Proxy

	overTCP bool

	handshaker types.Handshaker
	packetAuth types.Auth
}

func init() {
	point.RegisterProtocol(NewClient)
}

func NewClient(config *protocol.Protocol_Yuubinsya) point.WrapProxy {
	return func(dialer netapi.Proxy) (netapi.Proxy, error) {
		auth, err := NewAuth(config.Yuubinsya.GetUdpEncrypt(), []byte(config.Yuubinsya.Password))
		if err != nil {
			return nil, err
		}

		c := &client{
			dialer,
			config.Yuubinsya.UdpOverStream,
			NewHandshaker(
				false,
				config.Yuubinsya.GetTcpEncrypt(),
				[]byte(config.Yuubinsya.Password),
			),
			auth,
		}

		return c, nil
	}
}

func (c *client) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	conn, err := c.Proxy.Conn(ctx, addr)
	if err != nil {
		return nil, err
	}

	hconn, err := c.handshaker.Handshake(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}

	return newConn(hconn, addr, c.handshaker), nil
}

func (c *client) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	if !c.overTCP {
		packet, err := c.Proxy.PacketConn(ctx, addr)
		if err != nil {
			return nil, err
		}

		return NewAuthPacketConn(packet).WithTarget(addr).WithAuth(c.packetAuth).WithPrefix(true), nil
	}

	conn, err := c.Proxy.Conn(ctx, addr)
	if err != nil {
		return nil, err
	}

	hconn, err := c.handshaker.Handshake(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return newPacketConn(hconn, c.handshaker, false), nil
}

type PacketConn struct {
	headerWrote bool
	remain      int

	net.Conn

	handshaker types.Handshaker
	addr       netapi.Address

	hmux sync.Mutex
	rmux sync.Mutex

	r *bufio.Reader
}

func newPacketConn(conn net.Conn, handshaker types.Handshaker, server bool) *PacketConn {
	return &PacketConn{
		Conn:        conn,
		handshaker:  handshaker,
		headerWrote: server,
		r:           websocket.NewBufioReader(conn),
	}
}

func (c *PacketConn) WriteTo(payload []byte, addr net.Addr) (int, error) {
	taddr, err := netapi.ParseSysAddr(addr)
	if err != nil {
		return 0, fmt.Errorf("failed to parse addr: %w", err)
	}

	s5Addr := tools.ParseAddr(taddr)
	defer s5Addr.Free()

	w := pool.GetBuffer()
	defer pool.PutBuffer(w)

	if !c.headerWrote {
		c.hmux.Lock()
		if !c.headerWrote {
			c.handshaker.EncodeHeader(types.UDP, w, netapi.EmptyAddr)
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
		w.Write(s5Addr.Bytes.Bytes())
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
		n, err := c.r.Read(payload[:min(len(payload), c.remain)])
		c.remain -= n
		return n, c.addr, err
	}

	addr, err := tools.ResolveAddr(c.r)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to resolve udp packet addr: %w", err)
	}

	c.addr = addr.Address(statistic.Type_udp)

	lengthBytes, err := c.r.Peek(2)
	if err != nil {
		return 0, nil, fmt.Errorf("read length failed: %w", err)
	}

	_, _ = c.r.Discard(2)

	length := binary.BigEndian.Uint16(lengthBytes)

	readlen := min(len(payload), int(length))
	c.remain = int(length) - readlen

	n, err = io.ReadFull(c.r, payload[:readlen])
	return n, c.addr, err
}

type Conn struct {
	headerWrote bool

	net.Conn

	addr       netapi.Address
	handshaker types.Handshaker
}

func newConn(con net.Conn, addr netapi.Address, handshaker types.Handshaker) net.Conn {
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

	buf := pool.GetBytesWriter(pool.DefaultSize + len(b))
	defer buf.Free()

	c.handshaker.EncodeHeader(types.TCP, buf, c.addr)
	_, _ = buf.Write(b)

	if n, err := c.Conn.Write(buf.Bytes()); err != nil {
		return n, err
	}

	return len(b), nil
}
