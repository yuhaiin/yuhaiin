package shadowsocksr

import (
	"fmt"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocks"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr/cipher"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr/obfs"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr/protocol"
	ssr "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr/utils"
	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
)

var _ proxy.Proxy = (*Shadowsocksr)(nil)

type Shadowsocksr struct {
	proto  *protocol.Protocol
	obfss  *obfs.Obfs
	cipher *cipher.Cipher
	dial   proxy.Proxy

	udpAddr net.Addr
}

func NewShadowsocksr(config *node.PointProtocol_Shadowsocksr) node.WrapProxy {
	c := config.Shadowsocksr

	return func(p proxy.Proxy) (proxy.Proxy, error) {
		cipher, err := cipher.NewCipher(c.Method, c.Password)
		if err != nil {
			return nil, fmt.Errorf("new cipher failed: %w", err)
		}

		addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(c.Server, c.Port))
		if err != nil {
			return nil, fmt.Errorf("resolve udp addr failed: %w", err)
		}

		obfs, err := obfs.NewObfs(c.Obfs, ssr.ServerInfo{
			Host: c.Server, Port: uint16(addr.Port),
			Param:  c.Obfsparam,
			TcpMss: 1460,
			IVLen:  cipher.IVLen(), Key: cipher.Key(), KeyLen: cipher.KeyLen(),
		})
		if err != nil {
			return nil, fmt.Errorf("new obfs failed: %w", err)
		}
		protocol, err := protocol.NewProtocol(c.Protocol, ssr.ServerInfo{
			Host: c.Server, Port: uint16(addr.Port),
			Param:  c.Protoparam,
			TcpMss: 1460,
			IVLen:  cipher.IVLen(), Key: cipher.Key(), KeyLen: cipher.KeyLen(),
		}, obfs.Overhead())
		if err != nil {
			return nil, fmt.Errorf("new protocol failed: %w", err)
		}

		return &Shadowsocksr{cipher: cipher, dial: p, obfss: obfs, proto: protocol, udpAddr: addr}, nil
	}
}

func (s *Shadowsocksr) Conn(addr string) (net.Conn, error) {
	c, err := s.dial.Conn(addr)
	if err != nil {
		return nil, fmt.Errorf("get conn failed: %w", err)
	}
	// obfsServerInfo.SetHeadLen(b, 30)
	// protocolServerInfo.SetHeadLen(b, 30)
	obfs := s.obfss.StreamObfs(c)
	cipher := s.cipher.StreamCipher(obfs)
	conn := s.proto.StreamProtocol(cipher, cipher.WriteIV())
	target, err := s5c.ParseAddr(addr)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("parse addr failed: %w", err)
	}
	if _, err := conn.Write(target); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("write target failed: %w", err)
	}

	return conn, nil
}

func (s *Shadowsocksr) PacketConn(addr string) (net.PacketConn, error) {
	c, err := s.dial.PacketConn(addr)
	if err != nil {
		return nil, fmt.Errorf("get packet conn failed: %w", err)
	}
	cipher := s.cipher.PacketCipher(c)
	proto := s.proto.PacketProtocol(cipher)
	conn, err := shadowsocks.NewSsPacketConn(proto, s.udpAddr, addr)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("new ss packet conn failed: %w", err)
	}

	return conn, nil
}
