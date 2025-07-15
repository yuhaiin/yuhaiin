// modified from https://github.com/yaling888/clash/blob/plus-pro/transport/vless/vless.go
package vless

import (
	"context"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/google/uuid"
)

// Version of vmess
const Version byte = 0

// Command types
const (
	CommandTCP byte = 1
	CommandUDP byte = 2
)

// Addr types
const (
	AtypIPv4       byte = 1
	AtypDomainName byte = 2
	AtypIPv6       byte = 3
)

// DstAddr store destination address
type DstAddr struct {
	Addr     []byte
	Port     uint
	UDP      bool
	AddrType byte
}

// Client is vless connection generator
type Client struct {
	netapi.Proxy
	uuid uuid.UUID
}

func (c *Client) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	conn, err := c.Proxy.Conn(ctx, addr)
	if err != nil {
		return nil, err
	}

	return newConn(conn, c, false, addr)
}

func (c *Client) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	conn, err := c.Proxy.Conn(ctx, addr)
	if err != nil {
		return nil, err
	}

	return newConn(conn, c, true, addr)
}

func (c *Client) Ping(ctx context.Context, addr netapi.Address) (uint64, error) {
	return 0, nil
}

func init() {
	register.RegisterPoint(NewClient)
}

func NewClient(config *protocol.Vless, p netapi.Proxy) (netapi.Proxy, error) {
	uid, err := uuid.Parse(config.GetUuid())
	if err != nil {
		return nil, err
	}

	return &Client{Proxy: p, uuid: uid}, nil
}
