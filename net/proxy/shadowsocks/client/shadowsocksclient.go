package client

import (
	"log"
	"net"
	"strings"
	"time"

	"github.com/Asutorufa/yuhaiin/net/common"
	"github.com/shadowsocks/go-shadowsocks2/core"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

var (
	OBFS  = "obfs-local"
	V2RAY = "v2ray"
)

type shadowsocks struct {
	cipher     core.Cipher
	server     string
	plugin     string
	pluginOpt  string
	pluginFunc func(conn net.Conn) net.Conn
}

func NewShadowsocks(cipherName string, password string, server string, plugin, pluginOpt string) (*shadowsocks, error) {
	cipher, err := core.PickCipher(strings.ToUpper(cipherName), nil, password)
	if err != nil {
		return &shadowsocks{}, err
	}
	s := &shadowsocks{cipher: cipher, server: server, plugin: strings.ToUpper(plugin), pluginOpt: pluginOpt}
	switch strings.ToLower(plugin) {
	case OBFS:
		s.pluginFunc = func(conn net.Conn) net.Conn {
			conn, err := NewObfs(conn, pluginOpt)
			if err != nil {
				log.Println(err)
				return nil
			}
			return conn
		}
	case V2RAY:
		s.pluginFunc = func(conn net.Conn) net.Conn {
			conn, err := NewV2ray(conn, pluginOpt)
			if err != nil {
				log.Println(err)
				return nil
			}
			return conn
		}
	default:
		s.pluginFunc = func(conn net.Conn) net.Conn { return conn }
	}

	return s, nil
}

func (s *shadowsocks) Conn(host string) (conn net.Conn, err error) {
	var rConn net.Conn
	if rConn, err = net.DialTimeout("tcp", s.server, 5*time.Second); err != nil {
		return nil, err
	}
	_ = rConn.(*net.TCPConn).SetKeepAlive(true)
	conn = s.cipher.StreamConn(s.pluginFunc(rConn))
	if _, err = conn.Write(socks.ParseAddr(host)); err != nil {
		return nil, err
	}
	return conn, nil
}

func (s *shadowsocks) UDPConn(listener *net.UDPConn, target net.Addr, b []byte) (err error) {
	host, port, err := net.SplitHostPort(s.server)
	if err != nil {
		return err
	}
	ip, err := net.ResolveIPAddr("ip", host)
	if err != nil {
		return err
	}
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ip.String(), port))
	if err != nil {
		return err
	}

	pc, err := net.ListenPacket("udp", "")
	if err != nil {
		return err
	}
	pc = s.cipher.PacketConn(pc)

	_, err = pc.WriteTo(b[3:], addr)
	if err != nil {
		return err
	}

	buf := common.BuffPool.Get().([]byte)
	defer common.BuffPool.Put(buf[:cap(buf)])
	go func() {
		for {
			_ = pc.SetReadDeadline(time.Now().Add(time.Second * 5))
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				log.Println(err)
				break
			}
			_, err = listener.WriteTo(append([]byte{0, 0, 0}, buf[:n]...), target)
			if err != nil {
				log.Println(err)
				break
			}
		}
	}()
	return
}
