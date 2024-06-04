package yuubinsya

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/tools"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya/types"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/relay"
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

		return NewAuthPacketConn(packet).WithTarget(addr).WithAuth(c.packetAuth), nil
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

	net.Conn

	handshaker types.Handshaker

	hmux sync.Mutex
	rmux sync.Mutex
}

func newPacketConn(conn net.Conn, handshaker types.Handshaker, server bool) *PacketConn {
	return &PacketConn{
		Conn:        conn,
		handshaker:  handshaker,
		headerWrote: server,
	}
}

func (c *PacketConn) WriteTo(payload []byte, addr net.Addr) (int, error) {
	taddr, err := netapi.ParseSysAddr(addr)
	if err != nil {
		return 0, fmt.Errorf("failed to parse addr: %w", err)
	}

	w := pool.NewBufferSize(min(len(payload), nat.MaxSegmentSize) + 1024)
	defer w.Reset()

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

	tools.EncodeAddr(taddr, w)

	payload = payload[:min(nat.MaxSegmentSize, len(payload))]
	_ = binary.Write(w, binary.BigEndian, uint16(len(payload)))
	_, _ = w.Write(payload)

	_, err = c.Conn.Write(w.Bytes())
	if err != nil {
		return 0, err
	}

	return len(payload), nil
}

func readLength(r io.Reader) (uint16, error) {
	lengthBytes := pool.GetBytes(2)
	defer pool.PutBytes(lengthBytes)

	_, err := io.ReadFull(r, lengthBytes)
	if err != nil {
		return 0, fmt.Errorf("read length failed: %w", err)
	}

	return binary.BigEndian.Uint16(lengthBytes), nil
}

func (c *PacketConn) ReadFrom(payload []byte) (n int, _ net.Addr, err error) {
	c.rmux.Lock()
	defer c.rmux.Unlock()

	addr, err := tools.ResolveAddr(c.Conn)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to resolve udp packet addr: %w", err)
	}
	defer pool.PutBytes(addr)

	length, err := readLength(c.Conn)
	if err != nil {
		return 0, nil, fmt.Errorf("read length failed: %w", err)
	}

	n, err = io.ReadFull(c.Conn, payload[:min(len(payload), int(length))])

	_, _ = relay.CopyN(io.Discard, c.Conn, int64(int(length)-n))

	return n, addr.Address(statistic.Type_udp), err
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

	buf := pool.NewBufferSize(1024 + len(b))
	defer buf.Reset()

	c.handshaker.EncodeHeader(types.TCP, buf, c.addr)
	_, _ = buf.Write(b)

	if n, err := c.Conn.Write(buf.Bytes()); err != nil {
		return n, err
	}

	return len(b), nil
}
