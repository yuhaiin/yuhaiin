package shadowsocks

import (
	"bytes"
	"fmt"
	"net"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/shadowsocks/go-shadowsocks2/core"
)

//Shadowsocks shadowsocks
type Shadowsocks struct {
	cipher core.Cipher
	p      proxy.Proxy

	addr string
}

func NewShadowsocks(config *node.PointProtocol_Shadowsocks) node.WrapProxy {
	c := config.Shadowsocks
	return func(p proxy.Proxy) (proxy.Proxy, error) {
		cipher, err := core.PickCipher(strings.ToUpper(c.Method), nil, c.Password)
		if err != nil {
			return nil, err
		}

		return &Shadowsocks{cipher: cipher, p: p, addr: net.JoinHostPort(c.Server, c.Port)}, nil
	}
}

//Conn .
func (s *Shadowsocks) Conn(addr proxy.Address) (conn net.Conn, err error) {
	conn, err = s.p.Conn(addr)
	if err != nil {
		return nil, fmt.Errorf("dial to %s failed: %v", addr, err)
	}

	if x, ok := conn.(*net.TCPConn); ok {
		_ = x.SetKeepAlive(true)
	}

	conn = s.cipher.StreamConn(conn)
	if _, err = conn.Write(s5c.ParseAddr(addr)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("shadowsocks write target failed: %v", err)
	}
	return conn, nil
}

//PacketConn .
func (s *Shadowsocks) PacketConn(tar proxy.Address) (net.PacketConn, error) {
	pc, err := s.p.PacketConn(tar)
	if err != nil {
		return nil, fmt.Errorf("create packet conn failed")
	}
	pc = s.cipher.PacketConn(pc)

	uaddr, err := resolver.ResolveUDPAddr(s.addr)
	if err != nil {
		pc.Close()
		return nil, fmt.Errorf("resolve udp address failed: %v", err)
	}
	return NewSsPacketConn(pc, uaddr, tar), nil
}

type ssPacketConn struct {
	net.PacketConn
	add    *net.UDPAddr
	target []byte
}

func NewSsPacketConn(conn net.PacketConn, host *net.UDPAddr, target proxy.Address) net.PacketConn {
	return &ssPacketConn{PacketConn: conn, add: host, target: s5c.ParseAddr(target)}
}

func (v *ssPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, _, err := v.PacketConn.ReadFrom(b)
	if err != nil {
		return 0, nil, fmt.Errorf("read udp from shadowsocks failed: %v", err)
	}

	addr, addrSize, err := s5c.ResolveAddr(bytes.NewBuffer(b[:n]))
	if err != nil {
		return 0, nil, fmt.Errorf("resolve address failed: %v", err)
	}

	copy(b, b[addrSize:])
	return n - addrSize, addr, nil
}

func (v *ssPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	return v.PacketConn.WriteTo(bytes.Join([][]byte{v.target, b}, []byte{}), v.add)
}
