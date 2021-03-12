package shadowsocks

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

func ParseLink(str []byte, group string) (*utils.Point, error) {
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

	data, err := json.Marshal(n)
	if err != nil {
		return nil, fmt.Errorf("shadowsocks marshal failed: %v", err)
	}
	return &utils.Point{
		NodeMessage: n.NodeMessage,
		Data:        data,
	}, nil
}

func ParseConn(n *utils.Point) (func(string) (net.Conn, error), func(string) (net.PacketConn, error), error) {
	s := new(Shadowsocks)

	err := json.Unmarshal(n.Data, s)
	if err != nil {
		return nil, nil, err
	}
	ss, err := ssClient.NewShadowsocks(
		s.Method,
		s.Password,
		s.Server, s.Port,
		s.Plugin,
		s.PluginOpt,
	)
	if err != nil {
		return nil, nil, err
	}

	return ss.Conn, ss.UDPConn, nil
}
