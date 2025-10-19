package vmess

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/register"
)

// Vmess  client
type Vmess struct {
	client *Client
	netapi.Proxy
}

func init() {
	register.RegisterPoint(NewClient)
}

func NewClient(config *node.Vmess, p netapi.Proxy) (netapi.Proxy, error) {
	alterID, err := strconv.Atoi(config.GetAlterId())
	if err != nil {
		return nil, fmt.Errorf("convert AlterId to int failed: %w", err)
	}

	client, err := newClient(config.GetUuid(), config.GetSecurity(), alterID)
	if err != nil {
		return nil, fmt.Errorf("new vmess client failed: %w", err)
	}

	return &Vmess{client, p}, nil
}

// Conn create a connection for host
func (v *Vmess) Conn(ctx context.Context, host netapi.Address) (conn net.Conn, err error) {
	c, err := v.Proxy.Conn(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("get conn failed: %w", err)
	}
	conn, err = v.client.NewConn(c, host)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("new conn failed: %w", err)
	}

	return conn, nil
}

// PacketConn packet transport connection
func (v *Vmess) PacketConn(ctx context.Context, host netapi.Address) (conn net.PacketConn, err error) {
	c, err := v.Proxy.Conn(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("get conn failed: %w", err)
	}

	conn, err = v.client.NewPacketConn(c, host)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("new conn failed: %w", err)
	}

	return conn, nil
}

func (v *Vmess) Ping(ctx context.Context, addr netapi.Address) (uint64, error) {
	return 0, nil
}
