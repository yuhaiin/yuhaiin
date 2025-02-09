package shadowsocksr

import (
	"context"
	"fmt"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr/cipher"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr/obfs"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/tools"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya"
	protocols "github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

var _ netapi.Proxy = (*Shadowsocksr)(nil)

type Shadowsocksr struct {
	protocol *protocol.Protocol
	obfs     *obfs.Obfs
	cipher   *cipher.Cipher
	netapi.Proxy
}

func init() {
	register.RegisterPoint(NewClient)
}

func NewClient(c *protocols.Shadowsocksr, p netapi.Proxy) (netapi.Proxy, error) {
	cipher, err := cipher.NewCipher(c.GetMethod(), c.GetPassword())
	if err != nil {
		return nil, fmt.Errorf("new cipher failed: %w", err)
	}

	obfs := &obfs.Obfs{
		Name:   c.GetObfs(),
		Host:   c.GetServer(),
		Port:   c.GetPort(),
		Param:  c.GetObfsparam(),
		Cipher: cipher,
	}

	protocol := &protocol.Protocol{
		Name:         c.GetProtocol(),
		Auth:         protocol.NewAuth(),
		Param:        c.GetProtoparam(),
		TcpMss:       1460,
		Cipher:       cipher,
		ObfsOverhead: obfs.Overhead(),
	}

	return &Shadowsocksr{protocol: protocol, obfs: obfs, cipher: cipher, Proxy: p}, nil
}

func (s *Shadowsocksr) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	c, err := s.Proxy.Conn(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("get conn failed: %w", err)
	}
	// obfsServerInfo.SetHeadLen(b, 30)
	// protocolServerInfo.SetHeadLen(b, 30)
	obfs, err := s.obfs.Stream(c)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("obfs stream failed: %w", err)
	}
	cipher := s.cipher.StreamConn(obfs)

	var iv []byte
	if z, ok := cipher.(interface{ WriteIV() ([]byte, error) }); ok {
		iv, err = z.WriteIV()
		if err != nil {
			c.Close()
			return nil, fmt.Errorf("get write iv failed: %w", err)
		}
	}

	conn, err := s.protocol.Stream(cipher, iv)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("protocol stream failed: %w", err)
	}

	adr := tools.ParseAddr(addr)
	defer pool.PutBytes(adr)

	if _, err := conn.Write(adr); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("write target failed: %w", err)
	}

	return conn, nil
}

func (s *Shadowsocksr) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	c, err := s.Proxy.PacketConn(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("get packet conn failed: %w", err)
	}
	cipher := s.cipher.PacketConn(c)
	proto, err := s.protocol.Packet(cipher)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("protocol packet failed: %w", err)
	}

	return yuubinsya.NewAuthPacketConn(proto), nil
}
