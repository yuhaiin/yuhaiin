package shadowsocks

import (
	"bytes"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/shadowsocks/go-shadowsocks2/core"
)

//Shadowsocks shadowsocks
type Shadowsocks struct {
	cipher  core.Cipher
	p       proxy.Proxy
	udpAddr net.Addr
}

func NewShadowsocks(config *node.PointProtocol_Shadowsocks) node.WrapProxy {
	c := config.Shadowsocks
	return func(p proxy.Proxy) (proxy.Proxy, error) {
		cipher, err := core.PickCipher(strings.ToUpper(c.Method), nil, c.Password)
		if err != nil {
			return nil, err
		}

		addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(c.Server, c.Port))
		if err != nil {
			return nil, fmt.Errorf("resolve udp addr failed: %v", err)
		}

		return &Shadowsocks{cipher: cipher, p: p, udpAddr: addr}, nil
	}
}

//Conn .
func (s *Shadowsocks) Conn(host string) (conn net.Conn, err error) {
	conn, err = s.p.Conn(host)
	if err != nil {
		return nil, fmt.Errorf("dial to %s failed: %v", host, err)
	}

	if x, ok := conn.(*net.TCPConn); ok {
		_ = x.SetKeepAlive(true)
	}

	conn = s.cipher.StreamConn(conn)
	target, err := s5c.ParseAddr(host)
	if err != nil {
		return nil, fmt.Errorf("parse host failed: %v", err)
	}
	if _, err = conn.Write(target); err != nil {
		return nil, fmt.Errorf("shadowsocks write target failed: %v", err)
	}
	return conn, nil
}

//PacketConn .
func (s *Shadowsocks) PacketConn(tar string) (net.PacketConn, error) {
	pc, err := s.p.PacketConn(tar)
	if err != nil {
		return nil, fmt.Errorf("create packet conn failed")
	}
	pc = s.cipher.PacketConn(pc)

	return NewSsPacketConn(pc, s.udpAddr, tar)
}

type ssPacketConn struct {
	net.PacketConn
	add    net.Addr
	target []byte
}

func NewSsPacketConn(conn net.PacketConn, host net.Addr, target string) (net.PacketConn, error) {
	addr, err := s5c.ParseAddr(target)
	if err != nil {
		return nil, err
	}
	return &ssPacketConn{PacketConn: conn, add: host, target: addr}, nil
}

func (v *ssPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, _, err := v.PacketConn.ReadFrom(b)
	if err != nil {
		return 0, nil, fmt.Errorf("read udp from shadowsocks failed: %v", err)
	}

	host, port, addrSize, err := s5c.ResolveAddr(b[:n])
	if err != nil {
		return 0, nil, fmt.Errorf("resolve address failed: %v", err)
	}

	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.FormatInt(int64(port), 10)))
	if err != nil {
		return 0, nil, fmt.Errorf("resolve udp address failed: %v", err)
	}

	copy(b, b[addrSize:])
	return n - addrSize, addr, nil
}

func (v *ssPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	return v.PacketConn.WriteTo(bytes.Join([][]byte{v.target, b}, []byte{}), v.add)
}
