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
	hash []byte
	e    *encryptedHandshaker
}

func NewClient(cfg *protocol.Aead, p netapi.Proxy) (netapi.Proxy, error) {
	hash := Salt([]byte(cfg.GetPassword()))
	crypto := NewHandshaker(false, hash, []byte(cfg.GetPassword()))
	return &Client{Proxy: p, hash: hash, e: crypto}, nil
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

	auth, err := GetAuth(c.hash)
	if err != nil {
		return nil, err
	}

	return NewAuthPacketConn(pc, auth.AEAD), nil
}
