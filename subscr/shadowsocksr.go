package subscr

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"strings"

	ssrClient "github.com/Asutorufa/yuhaiin/net/proxy/shadowsocksr/client"
)

// Shadowsocksr node json struct
type Shadowsocksr struct {
	NodeMessage
	Server     string `json:"server"`
	Port       string `json:"port"`
	Method     string `json:"method"`
	Password   string `json:"password"`
	Obfs       string `json:"obfs"`
	Obfsparam  string `json:"obfsparam"`
	Protocol   string `json:"protocol"`
	Protoparam string `json:"protoparam"`
}

func SsrParse(link []byte) (*Shadowsocksr, error) {
	decodeStr := strings.Split(Base64DStr(strings.Replace(string(link), "ssr://", "", -1)), "/?")
	n := new(Shadowsocksr)
	n.NType = shadowsocksr
	x := strings.Split(decodeStr[0], ":")
	if len(x) != 6 {
		return n, errors.New("link: " + decodeStr[0] + " is not format Shadowsocksr link")
	}
	n.Server = x[0]
	n.Port = x[1]
	n.Protocol = x[2]
	n.Method = x[3]
	n.Obfs = x[4]
	n.Password = Base64DStr(x[5])
	if len(decodeStr) > 1 {
		query, _ := url.ParseQuery(decodeStr[1])
		n.NGroup = Base64DStr(query.Get("group"))
		n.Obfsparam = Base64DStr(query.Get("obfsparam"))
		n.Protoparam = Base64DStr(query.Get("protoparam"))
		n.NName = "[ssr]" + Base64DStr(query.Get("remarks"))
	}

	hash := sha256.New()
	hash.Write([]byte(n.Server))
	hash.Write([]byte(n.Port))
	hash.Write([]byte(n.Method))
	hash.Write([]byte(n.Password))
	hash.Write([]byte{byte(n.NType)})
	hash.Write([]byte(n.NGroup))
	hash.Write([]byte(n.NName))
	hash.Write([]byte(n.Obfs))
	hash.Write([]byte(n.Obfsparam))
	hash.Write([]byte(n.Protocol))
	hash.Write([]byte(n.Protoparam))
	n.NHash = hex.EncodeToString(hash.Sum(nil))
	return n, nil
}

func map2Shadowsocksr(n map[string]interface{}) (*Shadowsocksr, error) {
	if n == nil {
		return nil, errors.New("map is nil")
	}

	node := new(Shadowsocksr)
	node.NType = shadowsocksr

	for key := range n {
		switch key {
		case "server":
			node.Server = interface2string(n[key])
		case "port":
			node.Port = interface2string(n[key])
		case "method":
			node.Method = interface2string(n[key])
		case "password":
			node.Password = interface2string(n[key])
		case "obfs":
			node.Obfs = interface2string(n[key])
		case "obfsparam":
			node.Obfsparam = interface2string(n[key])
		case "protocol":
			node.Protocol = interface2string(n[key])
		case "protoparam":
			node.Protoparam = interface2string(n[key])
		case "name":
			node.NName = interface2string(n[key])
		case "group":
			node.NGroup = interface2string(n[key])
		case "hash":
			node.NHash = interface2string(n[key])
		}
	}
	return node, nil
}

func map2ShadowsocksrConn(n map[string]interface{}) (func(string) (net.Conn, error), error) {
	s, err := map2Shadowsocksr(n)
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
