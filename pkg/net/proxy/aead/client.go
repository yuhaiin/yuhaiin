package aead

import (
	"context"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/register"
)

func init() {
	register.RegisterPoint(NewClient)
}

type Client struct {
	netapi.Proxy
	e *encryptedHandshaker
}

func NewClient(cfg *protocol.Aead, p netapi.Proxy) (netapi.Proxy, error) {
	crypto := NewHandshaker(false, []byte(cfg.GetPassword()), cfg.GetCryptoMethod())
	return &Client{Proxy: p, e: crypto}, nil
}

func (c *Client) Conn(ctx context.Context, address netapi.Address) (net.Conn, error) {
	conn, err := c.Proxy.Conn(ctx, address)
	if err != nil {
		return nil, err
	}

	return c.e.Handshake(conn)
}

func (c *Client) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	pc, err := c.Proxy.PacketConn(ctx, addr)
	if err != nil {
		return nil, err
	}

	aead, err := newAead(c.e.aead, c.e.passwordHash)
	if err != nil {
		return nil, err
	}

	return NewAuthPacketConn(pc, aead), nil
}
