package shadowsocksr

import (
	"fmt"
	"net"
	"strconv"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocks"
	streamCipher "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr/cipher"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr/obfs"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr/protocol"
	ssr "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr/utils"
	socks5client "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
)

var _ proxy.Proxy = (*Shadowsocksr)(nil)

type Shadowsocksr struct {
	host   string
	proto  *protocol.Protocol
	obfss  *obfs.Obfs
	cipher *streamCipher.Cipher
	p      proxy.Proxy

	udpAddr net.Addr
}

func NewShadowsocksr(host, port string, method, password, obfss, obfsParam, protoc, protocolParam string) func(proxy.Proxy) (proxy.Proxy, error) {
	return func(p proxy.Proxy) (proxy.Proxy, error) {
		cipher, err := streamCipher.NewCipher(method, password)
		if err != nil {
			return nil, err
		}

		addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, port))
		if err != nil {
			return nil, err
		}

		port, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return nil, err
		}

		obfs, err := obfs.NewObfs(obfss, ssr.ServerInfo{
			Host:   host,
			Port:   uint16(port),
			Param:  obfsParam,
			TcpMss: 1460,
			IVLen:  cipher.IVLen(),
			Key:    cipher.Key(),
			KeyLen: cipher.KeyLen(),
		})
		if err != nil {
			return nil, err
		}
		protocol, err := protocol.NewProtocol(protoc, ssr.ServerInfo{
			Host:   host,
			Port:   uint16(port),
			Param:  protocolParam,
			TcpMss: 1460,
			IVLen:  cipher.IVLen(),
			Key:    cipher.Key(),
			KeyLen: cipher.KeyLen(),
		}, obfs.Overhead())
		if err != nil {
			return nil, err
		}

		s := &Shadowsocksr{
			host:    net.JoinHostPort(host, strconv.FormatUint(port, 10)),
			cipher:  cipher,
			p:       p,
			obfss:   obfs,
			proto:   protocol,
			udpAddr: addr,
		}
		return s, nil
	}
}

func (s *Shadowsocksr) Conn(addr string) (net.Conn, error) {
	c, err := s.p.Conn(addr)
	if err != nil {
		return nil, fmt.Errorf("get conn failed: %w", err)
	}
	// obfsServerInfo.SetHeadLen(b, 30)
	// protocolServerInfo.SetHeadLen(b, 30)
	obfs := s.obfss.StreamObfs(c)
	cipher := s.cipher.StreamCipher(obfs)
	conn := s.proto.StreamProtocol(cipher, cipher.WriteIV())
	target, err := socks5client.ParseAddr(addr)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(target); err != nil {
		_ = conn.Close()
		return nil, err
	}

	return conn, nil
}

func (s *Shadowsocksr) PacketConn(addr string) (net.PacketConn, error) {
	c, err := s.p.PacketConn(addr)
	if err != nil {
		return nil, err
	}
	cipher := s.cipher.PacketCipher(c)
	proto := s.proto.PacketProtocol(cipher)
	return shadowsocks.NewSsPacketConn(proto, s.udpAddr, addr)
}
