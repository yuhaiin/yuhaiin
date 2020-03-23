package client

import (
	"errors"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/shadowsocks/go-shadowsocks2/core"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

type shadowsocks struct {
	cipher    core.Cipher
	server    string
	plugin    string
	pluginOpt string
}

func NewShadowsocks(cipherName string, password string, server string, plugin, pluginOpt string) (*shadowsocks, error) {
	cipher, err := core.PickCipher(strings.ToUpper(cipherName), nil, password)
	if err != nil {
		return &shadowsocks{}, err
	}
	return &shadowsocks{cipher: cipher, server: server, plugin: strings.ToUpper(plugin), pluginOpt: pluginOpt}, nil
}

func (s *shadowsocks) Conn(host string) (conn net.Conn, err error) {
	rConn, err := net.DialTimeout("tcp", s.server, 4*time.Second)
	if err != nil {
		return nil, err
	}
	switch s.plugin {
	case "OBFS-LOCAL":
		opts := strings.Split(s.pluginOpt, ";")
		if len(opts) < 2 {
			return nil, errors.New("no format plugin options")
		}
		obfs := strings.Replace(opts[0], "obfs=", "", -1)
		param := strings.Replace(opts[1], "obfs-host=", "", -1)
		urlTmp, err := url.Parse("//" + host)
		if err != nil {
			return nil, err
		}
		switch obfs {
		case "http":
			conn = s.cipher.StreamConn(NewHTTPObfs(rConn, param, urlTmp.Port()))
		default:
			return nil, errors.New("now not support " + obfs)
		}
	default:
		conn = s.cipher.StreamConn(rConn)
	}
	if _, err = conn.Write(socks.ParseAddr(host)); err != nil {
		return nil, err
	}
	return conn, nil
}
