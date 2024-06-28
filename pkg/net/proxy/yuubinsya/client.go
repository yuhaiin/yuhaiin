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
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/relay"
)

type client struct {
	netapi.Proxy

	handshaker types.Handshaker
	packetAuth types.Auth

	overTCP bool
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
			NewHandshaker(
				false,
				config.Yuubinsya.GetTcpEncrypt(),
				[]byte(config.Yuubinsya.Password),
			),
			auth,
			config.Yuubinsya.UdpOverStream,
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

		return NewAuthPacketConn(packet).WithRealTarget(addr).WithAuth(c.packetAuth), nil
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
	pc := newPacketConn(hconn, c.handshaker)

	store := netapi.GetContext(ctx)

	migrate, err := pc.Handshake(store.UDPMigrateID)
	if err != nil {
		pc.Close()
		return nil, err
	}

	store.UDPMigrateID = migrate

	return pc, nil
}

type PacketConn struct {
	net.Conn
	handshaker types.Handshaker
	rmux       sync.Mutex
}

func newPacketConn(conn net.Conn, handshaker types.Handshaker) *PacketConn {
	return &PacketConn{
		Conn:       conn,
		handshaker: handshaker,
	}
}

// Handshake Handshake
// only used for client
func (c *PacketConn) Handshake(migrateID uint64) (uint64, error) {
	protocol := types.UDPWithMigrateID
	w := pool.NewBufferSize(1024)
	defer w.Reset()
	c.handshaker.EncodeHeader(types.Header{Protocol: protocol, MigrateID: migrateID}, w)
	_, err := c.Conn.Write(w.Bytes())
	if err != nil {
		return 0, err
	}

	if protocol == types.UDPWithMigrateID {
		id := pool.GetBytes(8)
		defer pool.PutBytes(id)

		if _, err := io.ReadFull(c, id); err != nil {
			return 0, fmt.Errorf("read net type failed: %w", err)
		}

		return binary.BigEndian.Uint64(id), nil
	}

	return 0, nil
}

func (c *PacketConn) WriteTo(payload []byte, addr net.Addr) (int, error) {
	taddr, err := netapi.ParseSysAddr(addr)
	if err != nil {
		return 0, fmt.Errorf("failed to parse addr: %w", err)
	}

	length := min(len(payload), nat.MaxSegmentSize)
	w := pool.NewBufferSize(length + 1024)
	defer w.Reset()
	tools.EncodeAddr(taddr, w)
	_ = binary.Write(w, binary.BigEndian, uint16(length))
	_, _ = w.Write(payload[:length])
	_, err = c.Conn.Write(w.Bytes())
	if err != nil {
		return 0, err
	}

	return len(payload), nil
}

func readLength(r io.Reader, lengthBytes []byte) (uint16, error) {
	if len(lengthBytes) < 2 {
		return 0, fmt.Errorf("read length failed: buf too short")
	}

	_, err := io.ReadFull(r, lengthBytes[:2])
	if err != nil {
		return 0, fmt.Errorf("read length failed: %w", err)
	}

	return binary.BigEndian.Uint16(lengthBytes[:2]), nil
}

func (c *PacketConn) ReadFrom(payload []byte) (n int, _ net.Addr, err error) {
	c.rmux.Lock()
	defer c.rmux.Unlock()

	addr, err := tools.ResolveAddr(c.Conn)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to resolve udp packet addr: %w", err)
	}
	defer pool.PutBytes(addr)

	length, err := readLength(c.Conn, payload)
	if err != nil {
		return 0, nil, fmt.Errorf("read length failed: %w", err)
	}

	n, err = io.ReadFull(c.Conn, payload[:min(len(payload), int(length))])
	if err != nil {
		return n, nil, fmt.Errorf("read data failed: %w", err)
	}

	_, _ = relay.CopyN(io.Discard, c.Conn, int64(int(length)-n))

	return n, addr.Address("udp"), nil
}

type Conn struct {
	net.Conn

	addr        netapi.Address
	handshaker  types.Handshaker
	headerWrote bool
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

	c.handshaker.EncodeHeader(types.Header{Protocol: types.TCP, Addr: c.addr}, buf)
	_, _ = buf.Write(b)

	if n, err := c.Conn.Write(buf.Bytes()); err != nil {
		return n, err
	}

	return len(b), nil
}
