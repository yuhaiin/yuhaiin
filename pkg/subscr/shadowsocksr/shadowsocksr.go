package shadowsocksr

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"

	ssrClient "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr"
	"github.com/Asutorufa/yuhaiin/pkg/subscr/utils"
)

// ParseLink parse a base64 encode ssr link
func ParseLink(link []byte, group string) (*utils.Point, error) {
	decodeStr := strings.Split(utils.DecodeUrlBase64(strings.Replace(string(link), "ssr://", "", -1)), "/?")

	p := &utils.Point{
		NOrigin: utils.Point_remote,
		NGroup:  group,
	}

	n := new(utils.Shadowsocksr)
	x := strings.Split(decodeStr[0], ":")
	if len(x) != 6 {
		return nil, errors.New("link: " + decodeStr[0] + " is not format Shadowsocksr link")
	}
	n.Server = x[0]
	n.Port = x[1]
	n.Protocol = x[2]
	n.Method = x[3]
	n.Obfs = x[4]
	n.Password = utils.DecodeUrlBase64(x[5])
	if len(decodeStr) > 1 {
		query, _ := url.ParseQuery(decodeStr[1])
		n.Obfsparam = utils.DecodeUrlBase64(query.Get("obfsparam"))
		n.Protoparam = utils.DecodeUrlBase64(query.Get("protoparam"))
		p.NName = "[ssr]" + utils.DecodeUrlBase64(query.Get("remarks"))
	}
	p.Node = &utils.Point_Shadowsocksr{Shadowsocksr: n}
	z := sha256.Sum256([]byte(p.String()))
	p.NHash = hex.EncodeToString(z[:])

	return p, nil
}

// ParseLinkManual parse a manual base64 encode ssr link
func ParseLinkManual(link []byte, group string) (*utils.Point, error) {
	s, err := ParseLink(link, group)
	if err != nil {
		return nil, err
	}
	s.NOrigin = utils.Point_manual
	return s, nil
}

// ParseConn parse a ssr map to conn function
func ParseConn(n *utils.Point) (proxy.Proxy, error) {
	s := n.GetShadowsocksr()
	if s == nil {
		return nil, fmt.Errorf("can't get shadowsocksr message")
	}
	ssr, err := ssrClient.NewShadowsocksrClient(
		s.Server, s.Port,
		s.Method,
		s.Password,
		s.Obfs, s.Obfsparam,
		s.Protocol, s.Protoparam,
	)
	if err != nil {
		return nil, err
	}
	return ssr, nil
}
