package yuubinsya

import (
	"context"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya/types"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

type client struct {
	netapi.Proxy

	handshaker types.Handshaker
	packetAuth types.Auth

	overTCP  bool
	coalesce bool
}

func init() {
	register.RegisterPoint(NewClient)
}

func NewClient(config *protocol.Yuubinsya, dialer netapi.Proxy) (netapi.Proxy, error) {
	auth, err := NewAuth(config.GetUdpEncrypt(), []byte(config.GetPassword()))
	if err != nil {
		return nil, err
	}

	c := &client{
		dialer,
		NewHandshaker(
			false,
			config.GetTcpEncrypt(),
			[]byte(config.GetPassword()),
		),
		auth,
		config.GetUdpOverStream(),
		config.GetUdpCoalesce(),
	}

	return c, nil
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

	buf := pool.NewBufferSize(1024)
	defer buf.Reset()

	c.handshaker.EncodeHeader(types.Header{Protocol: types.TCP, Addr: addr}, buf)

	_, err = hconn.Write(buf.Bytes())
	if err != nil {
		hconn.Close()
		return nil, err
	}

	return hconn, nil
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

	pc := newPacketConn(pool.NewBufioConnSize(hconn, configuration.UDPBufferSize.Load()),
		c.handshaker, c.coalesce)

	store := netapi.GetContext(ctx)

	migrate, err := pc.Handshake(store.GetUDPMigrateID())
	if err != nil {
		pc.Close()
		return nil, err
	}

	store.SetUDPMigrateID(migrate)

	return pc, nil
}
