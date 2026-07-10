package aead

import (
	"context"
	"net"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/register"
)

func init() {
	register.RegisterContractPoint("aead", func(config contractnode.AEAD, p netapi.Proxy) (netapi.Proxy, error) {
		return NewClient(Config{
			Password:     config.Password,
			CryptoMethod: contractCryptoMethod(config.CryptoMethod),
		}, p)
	})
}

type Client struct {
	netapi.Proxy
	e *encryptedHandshaker
}

type Config struct {
	Password     string       `json:"password"`
	CryptoMethod CryptoMethod `json:"crypto_method"`
}

func NewClient(cfg Config, p netapi.Proxy) (netapi.Proxy, error) {
	crypto := NewHandshaker(false, []byte(cfg.Password), cfg.CryptoMethod)
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

func contractCryptoMethod(value string) CryptoMethod {
	switch value {
	case "AeadCryptoMethod_XChacha20Poly1305", string(CryptoMethodXChacha20Poly1305):
		return CryptoMethodXChacha20Poly1305
	default:
		return CryptoMethodChacha20Poly1305
	}
}
