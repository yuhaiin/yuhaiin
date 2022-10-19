package shadowsocksr

import (
	"fmt"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocks"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr/cipher"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr/obfs"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr/protocol"
	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/pkg/net/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
)

var _ proxy.Proxy = (*Shadowsocksr)(nil)

type Shadowsocksr struct {
	protocol *protocol.Protocol
	obfs     *obfs.Obfs
	cipher   *cipher.Cipher
	dial     proxy.Proxy

	addr string
}

func NewShadowsocksr(config *node.Protocol_Shadowsocksr) node.WrapProxy {
	c := config.Shadowsocksr
	return func(p proxy.Proxy) (proxy.Proxy, error) {
		cipher, err := cipher.NewCipher(c.Method, c.Password)
		if err != nil {
			return nil, fmt.Errorf("new cipher failed: %w", err)
		}

		obfs := &obfs.Obfs{
			Name:   c.Obfs,
			Host:   c.Server,
			Port:   c.Port,
			Param:  c.Obfsparam,
			Cipher: cipher,
		}

		protocol := &protocol.Protocol{
			Name:         c.Protocol,
			Auth:         protocol.NewAuth(),
			Param:        c.Protoparam,
			TcpMss:       1460,
			Cipher:       cipher,
			ObfsOverhead: obfs.Overhead(),
		}

		return &Shadowsocksr{protocol, obfs, cipher, p, net.JoinHostPort(c.Server, c.Port)}, nil
	}
}

func (s *Shadowsocksr) Conn(addr proxy.Address) (net.Conn, error) {
	c, err := s.dial.Conn(addr)
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
	if _, err := conn.Write(s5c.ParseAddr(addr)); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("write target failed: %w", err)
	}

	return conn, nil
}

func (s *Shadowsocksr) PacketConn(addr proxy.Address) (net.PacketConn, error) {
	uaddr, err := resolver.ResolveUDPAddr(s.addr)
	if err != nil {
		return nil, fmt.Errorf("resolve udp addr failed: %w", err)
	}

	c, err := s.dial.PacketConn(addr)
	if err != nil {
		return nil, fmt.Errorf("get packet conn failed: %w", err)
	}
	cipher := s.cipher.PacketConn(c)
	proto, err := s.protocol.Packet(cipher)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("protocol packet failed: %w", err)
	}

	return shadowsocks.NewSsPacketConn(proto, uaddr, addr), nil
}
