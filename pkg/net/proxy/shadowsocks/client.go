package shadowsocks

import (
	"bytes"
	"fmt"
	"net"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/shadowsocks/go-shadowsocks2/core"
)

// Shadowsocks shadowsocks
type Shadowsocks struct {
	cipher core.Cipher
	p      proxy.Proxy
}

func New(config *protocol.Protocol_Shadowsocks) protocol.WrapProxy {
	c := config.Shadowsocks
	return func(p proxy.Proxy) (proxy.Proxy, error) {
		cipher, err := core.PickCipher(strings.ToUpper(c.Method), nil, c.Password)
		if err != nil {
			return nil, err
		}

		return &Shadowsocks{cipher: cipher, p: p}, nil
	}
}

// Conn .
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

// PacketConn .
func (s *Shadowsocks) PacketConn(tar proxy.Address) (net.PacketConn, error) {
	pc, err := s.p.PacketConn(tar)
	if err != nil {
		return nil, fmt.Errorf("create packet conn failed")
	}

	return NewSsPacketConn(s.cipher.PacketConn(pc)), nil
}

type ssPacketConn struct{ net.PacketConn }

func NewSsPacketConn(conn net.PacketConn) net.PacketConn {
	return &ssPacketConn{PacketConn: conn}
}

func (v *ssPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, _, err := v.PacketConn.ReadFrom(b)
	if err != nil {
		return 0, nil, fmt.Errorf("read udp from shadowsocks failed: %v", err)
	}

	addr, addrSize, err := s5c.ResolveAddr("udp", bytes.NewBuffer(b[:n]))
	if err != nil {
		return 0, nil, fmt.Errorf("resolve address failed: %v", err)
	}

	copy(b, b[addrSize:])
	return n - addrSize, addr, nil
}

func (v *ssPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	ad, err := proxy.ParseSysAddr(addr)
	if err != nil {
		return 0, err
	}
	return v.PacketConn.WriteTo(bytes.Join([][]byte{s5c.ParseAddr(ad), b}, nil), addr)
}
