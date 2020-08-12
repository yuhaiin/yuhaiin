package subscr

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"strings"

	ssClient "github.com/Asutorufa/yuhaiin/net/proxy/shadowsocks/client"
)

type Shadowsocks struct {
	NodeMessage
	Server    string `json:"server"`
	Port      string `json:"port"`
	Method    string `json:"method"`
	Password  string `json:"password"`
	Plugin    string `json:"plugin"`
	PluginOpt string `json:"plugin_opt"`
}

func ShadowSocksParse(str []byte) (*Shadowsocks, error) {
	n := new(Shadowsocks)
	ssUrl, err := url.Parse(string(str))
	if err != nil {
		return nil, err
	}
	n.NType = shadowsocks
	n.Server = ssUrl.Hostname()
	n.Port = ssUrl.Port()
	n.Method = strings.Split(Base64DStr(ssUrl.User.String()), ":")[0]
	n.Password = strings.Split(Base64DStr(ssUrl.User.String()), ":")[1]
	n.NGroup = Base64DStr(ssUrl.Query().Get("group"))
	n.Plugin = strings.Split(ssUrl.Query().Get("plugin"), ";")[0]
	n.PluginOpt = strings.Replace(ssUrl.Query().Get("plugin"), n.Plugin+";", "", -1)
	n.NName = "[ss]" + ssUrl.Fragment

	hash := sha256.New()
	hash.Write([]byte(n.Server))
	hash.Write([]byte(n.Port))
	hash.Write([]byte(n.Method))
	hash.Write([]byte(n.Password))
	hash.Write([]byte{byte(n.NType)})
	hash.Write([]byte(n.NGroup))
	hash.Write([]byte(n.NName))
	hash.Write([]byte(n.Plugin))
	hash.Write([]byte(n.PluginOpt))
	n.NHash = hex.EncodeToString(hash.Sum(nil))
	return n, nil
}

func map2Shadowsocks(n map[string]interface{}) (*Shadowsocks, error) {
	if n == nil {
		return nil, errors.New("map is nil")
	}
	node := new(Shadowsocks)
	node.NType = shadowsocks
	for key := range n {
		switch key {
		case "server":
			node.Server = interface2string(n[key])
		case "port":
			node.Port = interface2string(n[key])
		case "method":
			node.Method = interface2string(n[key])
		case "password":
			node.Password = interface2string(n[key])
		case "plugin":
			node.Plugin = interface2string(n[key])
		case "plugin_opt":
			node.PluginOpt = interface2string(n[key])
		case "name":
			node.NName = interface2string(n[key])
		case "group":
			node.NGroup = interface2string(n[key])
		case "hash":
			node.NHash = interface2string(n[key])
		}
	}
	return node, nil
}

func map2ShadowsocksConn(n map[string]interface{}) (func(string) (net.Conn, error), error) {
	s, err := map2Shadowsocks(n)
	if err != nil {
		return nil, err
	}
	ss, err := ssClient.NewShadowsocks(
		s.Method,
		s.Password,
		s.Server, s.Port,
		s.Plugin,
		s.PluginOpt,
	)
	if err != nil {
		return nil, err
	}

	return ss.Conn, nil
}
