package subscr

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"

	ssClient "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocks"
)

type shadowsocks struct{}

func (*shadowsocks) ParseLink(str []byte, group string) (*Point, error) {
	n := new(Shadowsocks)
	ssUrl, err := url.Parse(string(str))
	if err != nil {
		return nil, err
	}
	n.Server = ssUrl.Hostname()
	n.Port = ssUrl.Port()
	n.Method = strings.Split(DecodeUrlBase64(ssUrl.User.String()), ":")[0]
	n.Password = strings.Split(DecodeUrlBase64(ssUrl.User.String()), ":")[1]
	n.Plugin = strings.Split(ssUrl.Query().Get("plugin"), ";")[0]
	n.PluginOpt = strings.Replace(ssUrl.Query().Get("plugin"), n.Plugin+";", "", -1)

	p := &Point{
		NOrigin: Point_remote,
		NGroup:  group,
		NName:   "[ss]" + ssUrl.Fragment,
		Node:    &Point_Shadowsocks{Shadowsocks: n},
	}
	z := sha256.Sum256([]byte(p.String()))
	p.NHash = hex.EncodeToString(z[:])

	return p, nil
}

func (*shadowsocks) ParseConn(n *Point) (proxy.Proxy, error) {
	s := n.GetShadowsocks()
	if s == nil {
		return nil, fmt.Errorf("can't get shadowsocks message")
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
