package shadowsocksr

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"strings"

	"github.com/Asutorufa/yuhaiin/subscr/common"

	ssrClient "github.com/Asutorufa/yuhaiin/net/proxy/shadowsocksr/client"
)

// Shadowsocksr node json struct
type Shadowsocksr struct {
	common.NodeMessage
	Server     string `json:"server"`
	Port       string `json:"port"`
	Method     string `json:"method"`
	Password   string `json:"password"`
	Obfs       string `json:"obfs"`
	Obfsparam  string `json:"obfsparam"`
	Protocol   string `json:"protocol"`
	Protoparam string `json:"protoparam"`
}

func ParseLink(link []byte, group string) (*Shadowsocksr, error) {
	decodeStr := strings.Split(common.Base64DStr(strings.Replace(string(link), "ssr://", "", -1)), "/?")
	n := new(Shadowsocksr)
	n.NType = common.Shadowsocksr
	n.NOrigin = common.Remote
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
	n.Password = common.Base64DStr(x[5])
	if len(decodeStr) > 1 {
		query, _ := url.ParseQuery(decodeStr[1])
		n.Obfsparam = common.Base64DStr(query.Get("obfsparam"))
		n.Protoparam = common.Base64DStr(query.Get("protoparam"))
		n.NName = "[ssr]" + common.Base64DStr(query.Get("remarks"))
	}
	n.NHash = countHash(n)
	return n, nil
}

func ParseLinkManual(link []byte, group string) (*Shadowsocksr, error) {
	s, err := ParseLink(link, group)
	if err != nil {
		return nil, err
	}
	s.NOrigin = common.Manual
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

func ParseMap(n map[string]interface{}) (*Shadowsocksr, error) {
	if n == nil {
		return nil, errors.New("map is nil")
	}

	node := new(Shadowsocksr)
	node.NType = common.Shadowsocksr

	for key := range n {
		switch key {
		case "server":
			node.Server = common.Interface2string(n[key])
		case "port":
			node.Port = common.Interface2string(n[key])
		case "method":
			node.Method = common.Interface2string(n[key])
		case "password":
			node.Password = common.Interface2string(n[key])
		case "obfs":
			node.Obfs = common.Interface2string(n[key])
		case "obfsparam":
			node.Obfsparam = common.Interface2string(n[key])
		case "protocol":
			node.Protocol = common.Interface2string(n[key])
		case "protoparam":
			node.Protoparam = common.Interface2string(n[key])
		case "name":
			node.NName = common.Interface2string(n[key])
		case "group":
			node.NGroup = common.Interface2string(n[key])
		case "hash":
			node.NHash = common.Interface2string(n[key])
		}
	}
	if node.NHash == "" {
		node.NHash = countHash(node)
	}
	return node, nil
}

func ParseMapManual(m map[string]interface{}) (*Shadowsocksr, error) {
	s, err := ParseMap(m)
	if err != nil {
		return nil, err
	}
	s.NOrigin = common.Manual
	s.NHash = countHash(s)
	return s, nil
}

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
