package shadowsocksr

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"strings"

	ssrClient "github.com/Asutorufa/yuhaiin/net/proxy/shadowsocksr"
	"github.com/Asutorufa/yuhaiin/subscr/utils"
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
func ParseLink(link []byte, group string) (*Shadowsocksr, error) {
	decodeStr := strings.Split(utils.Base64UrlDStr(strings.Replace(string(link), "ssr://", "", -1)), "/?")
	n := new(Shadowsocksr)
	n.NType = utils.Shadowsocksr
	n.NOrigin = utils.Remote
	n.NGroup = group
	x := strings.Split(decodeStr[0], ":")
	if len(x) != 6 {
		return n, errors.New("link: " + decodeStr[0] + " is not format Shadowsocksr link")
	}
	n.Server = x[0]
	n.Port = x[1]
	n.Protocol = x[2]
	n.Method = x[3]
	n.Obfs = x[4]
	n.Password = utils.Base64UrlDStr(x[5])
	if len(decodeStr) > 1 {
		query, _ := url.ParseQuery(decodeStr[1])
		n.Obfsparam = utils.Base64UrlDStr(query.Get("obfsparam"))
		n.Protoparam = utils.Base64UrlDStr(query.Get("protoparam"))
		n.NName = "[ssr]" + utils.Base64UrlDStr(query.Get("remarks"))
	}
	n.NHash = countHash(n)
	return n, nil
}

// ParseLinkManual parse a manual base64 encode ssr link
func ParseLinkManual(link []byte, group string) (*Shadowsocksr, error) {
	s, err := ParseLink(link, group)
	if err != nil {
		return nil, err
	}
	s.NOrigin = utils.Manual
	return s, nil
}

func countHash(n *Shadowsocksr) string {
	if n == nil {
		return ""
	}
	hash := sha256.New()
	hash.Write([]byte{byte(n.NType)})
	hash.Write([]byte{byte(n.NOrigin)})
	hash.Write([]byte(n.Server))
	hash.Write([]byte(n.Port))
	hash.Write([]byte(n.Method))
	hash.Write([]byte(n.Password))
	hash.Write([]byte(n.NGroup))
	hash.Write([]byte(n.NName))
	hash.Write([]byte(n.Obfs))
	hash.Write([]byte(n.Obfsparam))
	hash.Write([]byte(n.Protocol))
	hash.Write([]byte(n.Protoparam))
	return hex.EncodeToString(hash.Sum(nil))
}

// ParseMap parse ssr map read from config json
func ParseMap(n map[string]interface{}) (*Shadowsocksr, error) {
	if n == nil {
		return nil, errors.New("map is nil")
	}

	node := new(Shadowsocksr)
	node.NType = utils.Shadowsocksr
	node.Server = utils.I2String(n["server"])
	node.Port = utils.I2String(n["port"])
	node.Method = utils.I2String(n["method"])
	node.Password = utils.I2String(n["password"])
	node.Obfs = utils.I2String(n["obfs"])
	node.Obfsparam = utils.I2String(n["obfsparam"])
	node.Protocol = utils.I2String(n["protocol"])
	node.Protoparam = utils.I2String(n["protoparam"])
	node.NName = utils.I2String(n["name"])
	node.NGroup = utils.I2String(n["group"])
	node.NHash = utils.I2String(n["hash"])
	if node.NHash == "" {
		node.NHash = countHash(node)
	}
	return node, nil
}

// ParseMapManual parse a ssr map to manual
func ParseMapManual(m map[string]interface{}) (*Shadowsocksr, error) {
	s, err := ParseMap(m)
	if err != nil {
		return nil, err
	}
	s.NOrigin = utils.Manual
	s.NHash = countHash(s)
	return s, nil
}

// ParseConn parse a ssr map to conn function
func ParseConn(n map[string]interface{}) (func(string) (net.Conn, error), error) {
	s, err := ParseMap(n)
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
	return ssr.Conn, nil
}
