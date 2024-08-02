package yuubinsya

import (
	"context"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya/types"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
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
