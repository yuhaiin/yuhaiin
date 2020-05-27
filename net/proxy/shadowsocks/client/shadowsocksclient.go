package client

import (
	"errors"
	"log"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/shadowsocks/go-shadowsocks2/core"
	"github.com/shadowsocks/go-shadowsocks2/socks"
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
	case "obfs-local":
		opts := strings.Split(pluginOpt, ";")
		if len(opts) < 2 {
			return nil, errors.New("no format plugin options")
		}
		obfs := strings.Replace(opts[0], "obfs=", "", -1)
		param := strings.Replace(opts[1], "obfs-host=", "", -1)
		switch obfs {
		case "http":
			urlTmp, err := url.Parse("//" + server)
			if err != nil {
				return nil, err
			}
			s.pluginFunc = func(conn net.Conn) net.Conn {
				return NewHTTPObfs(conn, param, urlTmp.Port())
			}
		default:
			return s, errors.New("not support plugin")
		}
	case "v2ray":
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
