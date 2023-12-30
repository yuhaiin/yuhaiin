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
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
)

// Shadowsocks shadowsocks
type Shadowsocks struct {
	cipher core.Cipher
	p      netapi.Proxy
	netapi.EmptyDispatch
}

func init() {
	point.RegisterProtocol(NewClient)
}

func NewClient(config *protocol.Protocol_Shadowsocks) point.WrapProxy {
	c := config.Shadowsocks
	return func(p netapi.Proxy) (netapi.Proxy, error) {
		cipher, err := core.PickCipher(strings.ToUpper(c.Method), nil, c.Password)
		if err != nil {
			return nil, err
		}

		return &Shadowsocks{cipher: cipher, p: p}, nil
	}
}

// Conn .
func (s *Shadowsocks) Conn(ctx context.Context, addr netapi.Address) (conn net.Conn, err error) {
	conn, err = s.p.Conn(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("dial to %s failed: %w", addr, err)
	}

	if x, ok := conn.(*net.TCPConn); ok {
		_ = x.SetKeepAlive(true)
	}

	conn = s.cipher.StreamConn(conn)
	if _, err = conn.Write(tools.ParseAddr(addr)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("shadowsocks write target failed: %w", err)
	}
	return conn, nil
}

// PacketConn .
func (s *Shadowsocks) PacketConn(ctx context.Context, tar netapi.Address) (net.PacketConn, error) {
	pc, err := s.p.PacketConn(ctx, tar)
	if err != nil {
		return nil, fmt.Errorf("create packet conn failed")
	}

	return yuubinsya.NewAuthPacketConn(s.cipher.PacketConn(pc), nil, netapi.EmptyAddr, nil, false), nil
}
