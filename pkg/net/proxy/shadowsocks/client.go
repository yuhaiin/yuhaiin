package shadowsocks

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"

	ss5client "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	ss5server "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/server"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
	"github.com/shadowsocks/go-shadowsocks2/core"
)

var (
	//OBFS plugin
	OBFS = "obfs-local"
	//V2RAY websocket and quic plugin
	V2RAY = "v2ray"
)

//Shadowsocks shadowsocks
type Shadowsocks struct {
	cipher     core.Cipher
	server     string
	port       string
	plugin     string
	pluginOpt  string
	pluginFunc func(conn net.Conn) (net.Conn, error)

	*utils.ClientUtil
}

//NewShadowsocks new shadowsocks client
func NewShadowsocks(cipherName string, password string, server, port string,
	plugin, pluginOpt string) (proxy.Proxy, error) {
	cipher, err := core.PickCipher(strings.ToUpper(cipherName), nil, password)
	if err != nil {
		return nil, err
	}
	s := &Shadowsocks{
		cipher:    cipher,
		server:    server,
		port:      port,
		plugin:    strings.ToUpper(plugin),
		pluginOpt: pluginOpt,

		ClientUtil: utils.NewClientUtil(server, port),
	}
	switch strings.ToLower(plugin) {
	case OBFS:
		s.pluginFunc = func(conn net.Conn) (net.Conn, error) {
			conn, err := NewObfs(conn, pluginOpt)
			if err != nil {
				log.Println(err)
				return nil, fmt.Errorf("create obfs plugin failed: %v", err)
			}
			return conn, nil
		}
	case V2RAY:
		s.pluginFunc = func(conn net.Conn) (net.Conn, error) {
			conn, err := NewV2raySelf(conn, pluginOpt)
			if err != nil {
				log.Println(err)
				return nil, fmt.Errorf("create v2ray plugin failed: %v", err)
			}
			return conn, nil
		}
	default:
		s.pluginFunc = func(conn net.Conn) (net.Conn, error) { return conn, nil }
	}

	return s, nil
}

//Conn .
func (s *Shadowsocks) Conn(host string) (conn net.Conn, err error) {
	conn, err = s.GetConn()
	if err != nil {
		return nil, fmt.Errorf("dial to %s failed: %v", s.server, err)
	}

	if x, ok := conn.(*net.TCPConn); ok {
		_ = x.SetKeepAlive(true)
	}

	conn, err = s.pluginFunc(conn)
	if err != nil {
		return nil, fmt.Errorf("plugin exec failed: %v", err)
	}
	conn = s.cipher.StreamConn(conn)

	target, err := ss5client.ParseAddr(host)
	if err != nil {
		return nil, fmt.Errorf("parse host failed: %v", err)
	}

	if _, err = conn.Write(target); err != nil {
		return nil, fmt.Errorf("shadowsocks write target failed: %v", err)
	}
	return conn, nil
}

//PacketConn .
func (s *Shadowsocks) PacketConn(string) (net.PacketConn, error) {
	ip, err := net.ResolveIPAddr("ip", s.server)
	if err != nil {
		return nil, fmt.Errorf("resolve ip failed: %v", err)
	}
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ip.String(), s.port))
	if err != nil {
		return nil, fmt.Errorf("resolve udp addr failed: %v", err)
	}

	pc, err := net.ListenPacket("udp", "")
	if err != nil {
		return nil, fmt.Errorf("create packet conn failed")
	}
	pc = s.cipher.PacketConn(pc)

	return &ssPacketConn{
		PacketConn: pc,
		add:        addr,
	}, nil
}

type ssPacketConn struct {
	net.PacketConn
	add net.Addr
}

func (v *ssPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, _, err := v.PacketConn.ReadFrom(b)
	if err != nil {
		return 0, nil, fmt.Errorf("read udp from shadowsocks failed: %v", err)
	}

	host, port, addrSize, err := ss5server.ResolveAddr(b[:n])
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

func (v *ssPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	target, err := ss5client.ParseAddr(addr.String())
	if err != nil {
		return 0, fmt.Errorf("parse target failed: %v", err)
	}
	return v.PacketConn.WriteTo(bytes.Join([][]byte{target, b}, []byte{}), v.add)
}
