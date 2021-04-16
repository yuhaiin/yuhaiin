package shadowsocksr

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	netUtils "github.com/Asutorufa/yuhaiin/pkg/net/utils"

	ssrClient "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr"
	"github.com/Asutorufa/yuhaiin/pkg/subscr/utils"
)

// Shadowsocksr node json struct
type Shadowsocksr struct {
	utils.NodeMessage
	Server     string `json:"server"`
	Port       string `json:"port"`
	Method     string `json:"method"`
	Password   string `json:"password"`
	Obfs       string `json:"obfs"`
	Obfsparam  string `json:"obfsparam"`
	Protocol   string `json:"protocol"`
	Protoparam string `json:"protoparam"`
}

// ParseLink parse a base64 encode ssr link
func ParseLink(link []byte, group string) (*utils.Point, error) {
	decodeStr := strings.Split(utils.DecodeUrlBase64(strings.Replace(string(link), "ssr://", "", -1)), "/?")
	n := new(Shadowsocksr)
	n.NType = utils.Shadowsocksr
	n.NOrigin = utils.Remote
	n.NGroup = group
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
		n.NName = "[ssr]" + utils.DecodeUrlBase64(query.Get("remarks"))
	}

	hash := sha256.New()
	hash.Write([]byte{byte(n.NType)})
	hash.Write([]byte{byte(n.NOrigin)})
	hash.Write([]byte(n.NGroup))
	hash.Write([]byte(n.NName))
	hash.Write(link)
	n.NHash = hex.EncodeToString(hash.Sum(nil))

	data, err := json.Marshal(n)
	if err != nil {
		return nil, fmt.Errorf("shadowsocksr marshal failed: %v", err)
	}
	return &utils.Point{
		NodeMessage: n.NodeMessage,
		Data:        data,
	}, nil
}

// ParseLinkManual parse a manual base64 encode ssr link
func ParseLinkManual(link []byte, group string) (*utils.Point, error) {
	s, err := ParseLink(link, group)
	if err != nil {
		return nil, err
	}
	s.NOrigin = utils.Manual
	return s, nil
}

// ParseConn parse a ssr map to conn function
func ParseConn(n *utils.Point) (netUtils.Proxy, error) {
	s := new(Shadowsocksr)
	err := json.Unmarshal(n.Data, s)
	if err != nil {
		return nil, err
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
