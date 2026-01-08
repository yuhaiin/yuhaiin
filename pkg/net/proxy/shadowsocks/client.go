package shadowsocks

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocks/core"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/tools"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/register"
)

// Shadowsocks shadowsocks
type Shadowsocks struct {
	cipher core.Cipher
	netapi.Proxy
}

func init() {
	register.RegisterPoint(NewClient)
}

func NewClient(c *node.Shadowsocks, p netapi.Proxy) (netapi.Proxy, error) {
	cipher, err := core.PickCipher(strings.ToUpper(c.GetMethod()), nil, c.GetPassword())
	if err != nil {
		return nil, err
	}

	return &Shadowsocks{cipher: cipher, Proxy: p}, nil
}

// Conn .
func (s *Shadowsocks) Conn(ctx context.Context, addr netapi.Address) (conn net.Conn, err error) {
	conn, err = s.Proxy.Conn(ctx, addr)
	if err != nil {
		return nil, netapi.NewDialError("tcp", err, addr)
	}

	adr := tools.ParseAddr(addr)
	defer pool.PutBytes(adr)

	conn = s.cipher.StreamConn(conn)
	if _, err = conn.Write(adr); err != nil {
		conn.Close()
		return nil, fmt.Errorf("shadowsocks write target failed: %w", err)
	}
	return conn, nil
}

// PacketConn .
func (s *Shadowsocks) PacketConn(ctx context.Context, tar netapi.Address) (net.PacketConn, error) {
	pc, err := s.Proxy.PacketConn(ctx, tar)
	if err != nil {
		return nil, fmt.Errorf("create packet conn failed")
	}

	return yuubinsya.NewAuthPacketConn(s.cipher.PacketConn(pc)), nil
}

func (s *Shadowsocks) Ping(ctx context.Context, addr netapi.Address) (uint64, error) {
	return 0, nil
}
