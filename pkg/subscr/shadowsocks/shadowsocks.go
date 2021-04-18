package shadowsocks

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	"google.golang.org/protobuf/encoding/protojson"

	ssClient "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocks"
	"github.com/Asutorufa/yuhaiin/pkg/subscr/utils"
)

func ParseLink(str []byte, group string) (*utils.Point, error) {
	n := new(utils.Shadowsocks)
	ssUrl, err := url.Parse(string(str))
	if err != nil {
		return nil, err
	}
	n.Server = ssUrl.Hostname()
	n.Port = ssUrl.Port()
	n.Method = strings.Split(utils.DecodeUrlBase64(ssUrl.User.String()), ":")[0]
	n.Password = strings.Split(utils.DecodeUrlBase64(ssUrl.User.String()), ":")[1]
	n.Plugin = strings.Split(ssUrl.Query().Get("plugin"), ";")[0]
	n.PluginOpt = strings.Replace(ssUrl.Query().Get("plugin"), n.Plugin+";", "", -1)

	d, err := protojson.Marshal(n)
	if err != nil {
		return nil, fmt.Errorf("marshal to json failed: %v", err)
	}
	p := &utils.Point{
		NType:   utils.Point_shadowsocks,
		NOrigin: utils.Point_remote,
		NGroup:  group,
		NName:   "[ss]" + ssUrl.Fragment,
		Data:    d,
	}
	z := sha256.Sum256([]byte(p.String()))
	p.NHash = hex.EncodeToString(z[:])

	return p, nil
}

func ParseConn(n *utils.Point) (proxy.Proxy, error) {
	s := new(utils.Shadowsocks)

	err := protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(n.Data, s)
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
