package shadowsocks

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	netUtils "github.com/Asutorufa/yuhaiin/pkg/net/utils"

	ssClient "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocks"
	"github.com/Asutorufa/yuhaiin/pkg/subscr/utils"
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
	hash.Write([]byte(n.NGroup))
	hash.Write([]byte(n.NName))
	hash.Write(str)
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

func ParseConn(n *utils.Point) (netUtils.Proxy, error) {
	s := new(Shadowsocks)

	err := json.Unmarshal(n.Data, s)
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

	return ss, nil
}
