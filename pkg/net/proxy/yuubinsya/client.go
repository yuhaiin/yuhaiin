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

	overTCP bool
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

	pc := newPacketConn(pool.NewBufioConnSize(hconn, configuration.UDPBufferSize.Load()), c.handshaker)

	store := netapi.GetContext(ctx)

	migrate, err := pc.Handshake(store.UDPMigrateID)
	if err != nil {
		pc.Close()
		return nil, err
	}

	store.UDPMigrateID = migrate

	return pc, nil
}
