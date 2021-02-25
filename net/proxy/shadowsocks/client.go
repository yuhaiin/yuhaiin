package shadowsocks

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/Asutorufa/yuhaiin/net/common"
	"github.com/shadowsocks/go-shadowsocks2/core"
	"github.com/shadowsocks/go-shadowsocks2/socks"
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
	pluginFunc func(conn net.Conn) net.Conn

	common.ClientUtil
}

//NewShadowsocks new shadowsocks client
func NewShadowsocks(cipherName string, password string, server, port string,
	plugin, pluginOpt string) (*Shadowsocks, error) {
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

		ClientUtil: common.NewClientUtil(server, port),
	}
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
			conn, err := NewV2raySelf(conn, pluginOpt)
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

//Conn .
func (s *Shadowsocks) Conn(host string) (conn net.Conn, err error) {
	conn, err = s.GetConn()
	if err != nil {
		return nil, fmt.Errorf("[ss] dial to %s -> %v", s.server, err)
	}
	_ = conn.(*net.TCPConn).SetKeepAlive(true)
	conn = s.cipher.StreamConn(s.pluginFunc(conn))
	if _, err = conn.Write(socks.ParseAddr(host)); err != nil {
		return nil, fmt.Errorf("conn.Write -> host: %s, error: %v", host, err)
	}
	return conn, nil
}

func (s *Shadowsocks) udpHandle(listener *net.UDPConn, remoteAddr net.Addr, b []byte) error {
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

	respBuff := common.BuffPool.Get().([]byte)
	defer common.BuffPool.Put(respBuff[:cap(respBuff)])
	n, _, err := pc.ReadFrom(respBuff)
	if err != nil {
		return err
	}

	_, err = listener.WriteTo(append([]byte{0, 0, 0}, respBuff[:n]...), remoteAddr)
	return err
}

//UDPConn .
func (s *Shadowsocks) UDPConn(listener net.PacketConn, target net.Addr, b []byte) (err error) {
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
	defer common.BuffPool.Put(buf)
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
