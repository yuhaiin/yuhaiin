package client

import (
	"log"
	"net"
	"strings"
	"time"

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
		s.pluginFunc = nil
	}
	return s, nil
}

func (s *shadowsocks) Conn(host string) (conn net.Conn, err error) {
	rConn, err := net.DialTimeout("tcp", s.server, 4*time.Second)
	if err != nil {
		return nil, err
	}
	_ = rConn.(*net.TCPConn).SetKeepAlive(true)
	if s.pluginFunc != nil {
		conn = s.cipher.StreamConn(s.pluginFunc(rConn))
	} else {
		conn = s.cipher.StreamConn(rConn)
	}

	if _, err = conn.Write(socks.ParseAddr(host)); err != nil {
		return nil, err
	}
	return conn, nil
}
