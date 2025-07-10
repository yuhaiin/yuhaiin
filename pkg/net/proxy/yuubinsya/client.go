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

	hash []byte

	overTCP  bool
	coalesce bool
}

func init() {
	register.RegisterPoint(NewClient)
}

func NewClient(config *protocol.Yuubinsya, dialer netapi.Proxy) (netapi.Proxy, error) {
	hash := Salt([]byte(config.GetPassword()))
	c := &client{
		dialer,
		hash,
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

	buf := pool.NewBufferSize(1024)
	defer buf.Reset()

	Handshaker(c.hash).EncodeHeader(types.Header{Protocol: types.TCP, Addr: addr}, buf)

	_, err = conn.Write(buf.Bytes())
	if err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

func (c *client) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	if !c.overTCP {
		packet, err := c.Proxy.PacketConn(ctx, addr)
		if err != nil {
			return nil, err
		}

		return NewAuthPacketConn(packet).WithRealTarget(addr), nil
	}

	conn, err := c.Proxy.Conn(ctx, addr)
	if err != nil {
		return nil, err
	}

	pc := newPacketConn(pool.NewBufioConnSize(conn, configuration.UDPBufferSize.Load()),
		c.hash, c.coalesce)

	store := netapi.GetContext(ctx)

	migrate, err := pc.Handshake(store.GetUDPMigrateID())
	if err != nil {
		pc.Close()
		return nil, err
	}

	store.SetUDPMigrateID(migrate)

	return pc, nil
}
