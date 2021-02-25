package shadowsocks

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"strings"

	ssClient "github.com/Asutorufa/yuhaiin/net/proxy/shadowsocks"
	"github.com/Asutorufa/yuhaiin/subscr/utils"
)

type Shadowsocks struct {
	utils.NodeMessage
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
	n.NType = utils.Shadowsocks
	n.NOrigin = utils.Remote
	n.Server = ssUrl.Hostname()
	n.Port = ssUrl.Port()
	n.Method = strings.Split(utils.Base64UrlDStr(ssUrl.User.String()), ":")[0]
	n.Password = strings.Split(utils.Base64UrlDStr(ssUrl.User.String()), ":")[1]
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
	node.NType = utils.Shadowsocks
	node.Server = utils.I2String(n["server"])
	node.Port = utils.I2String(n["port"])
	node.Method = utils.I2String(n["method"])
	node.Password = utils.I2String(n["password"])
	node.Plugin = utils.I2String(n["plugin"])
	node.PluginOpt = utils.I2String(n["plugin_opt"])
	node.NName = utils.I2String(n["name"])
	node.NGroup = utils.I2String(n["group"])
	node.NHash = utils.I2String(n["hash"])
	return node, nil
}

func ParseMapManual(m map[string]interface{}) (*Shadowsocks, error) {
	s, err := ParseMap(m)
	if err != nil {
		return nil, err
	}
	s.NOrigin = utils.Manual
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
