package shadowsocks

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"strings"

	"github.com/Asutorufa/yuhaiin/subscr/common"

	ssClient "github.com/Asutorufa/yuhaiin/net/proxy/shadowsocks"
)

type Shadowsocks struct {
	common.NodeMessage
	Server    string `json:"server"`
	Port      string `json:"port"`
	Method    string `json:"method"`
	Password  string `json:"password"`
	Plugin    string `json:"plugin"`
	PluginOpt string `json:"plugin_opt"`
}

func ParseLink(str []byte, group string) (*Shadowsocks, error) {
	n := new(Shadowsocks)
	ssUrl, err := url.Parse(string(str))
	if err != nil {
		return nil, err
	}
	n.NType = common.Shadowsocks
	n.NOrigin = common.Remote
	n.Server = ssUrl.Hostname()
	n.Port = ssUrl.Port()
	n.Method = strings.Split(common.Base64UrlDStr(ssUrl.User.String()), ":")[0]
	n.Password = strings.Split(common.Base64UrlDStr(ssUrl.User.String()), ":")[1]
	n.NGroup = group
	n.Plugin = strings.Split(ssUrl.Query().Get("plugin"), ";")[0]
	n.PluginOpt = strings.Replace(ssUrl.Query().Get("plugin"), n.Plugin+";", "", -1)
	n.NName = "[ss]" + ssUrl.Fragment

	hash := sha256.New()
	hash.Write([]byte{byte(n.NType)})
	hash.Write([]byte{byte(n.NOrigin)})
	hash.Write([]byte(n.Server))
	hash.Write([]byte(n.Port))
	hash.Write([]byte(n.Method))
	hash.Write([]byte(n.Password))
	hash.Write([]byte(n.NGroup))
	hash.Write([]byte(n.NName))
	hash.Write([]byte(n.Plugin))
	hash.Write([]byte(n.PluginOpt))
	n.NHash = hex.EncodeToString(hash.Sum(nil))
	return n, nil
}

func ParseMap(n map[string]interface{}) (*Shadowsocks, error) {
	if n == nil {
		return nil, errors.New("map is nil")
	}
	node := new(Shadowsocks)
	node.NType = common.Shadowsocks
	node.Server = common.I2string(n["server"])
	node.Port = common.I2string(n["port"])
	node.Method = common.I2string(n["method"])
	node.Password = common.I2string(n["password"])
	node.Plugin = common.I2string(n["plugin"])
	node.PluginOpt = common.I2string(n["plugin_opt"])
	node.NName = common.I2string(n["name"])
	node.NGroup = common.I2string(n["group"])
	node.NHash = common.I2string(n["hash"])
	return node, nil
}

func ParseMapManual(m map[string]interface{}) (*Shadowsocks, error) {
	s, err := ParseMap(m)
	if err != nil {
		return nil, err
	}
	s.NOrigin = common.Manual
	return s, nil
}

func ParseConn(n map[string]interface{}) (func(string) (net.Conn, error), error) {
	s, err := ParseMap(n)
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
