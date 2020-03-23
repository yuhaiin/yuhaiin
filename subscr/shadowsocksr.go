package subscr

import (
	"errors"
	"net/url"
	"strings"
)

// Shadowsocksr node json struct
type Shadowsocksr struct {
	ID         int     `json:"id"`
	Type       float64 `json:"type"`
	Server     string  `json:"server"`
	Port       string  `json:"port"`
	Method     string  `json:"method"`
	Password   string  `json:"password"`
	Obfs       string  `json:"obfs"`
	Obfsparam  string  `json:"obfsparam"`
	Protocol   string  `json:"protocol"`
	Protoparam string  `json:"protoparam"`
	Name       string  `json:"name"`
	Group      string  `json:"group"`
}

func SsrParse2(link []byte) (*Shadowsocksr, error) {
	decodeStr := strings.Split(Base64d(strings.Replace(string(link), "ssr://", "", -1)), "/?")
	node := new(Shadowsocksr)
	node.Type = shadowsocksr
	x := strings.Split(decodeStr[0], ":")
	if len(x) != 6 {
		return node, errors.New("link: " + decodeStr[0] + " is not format Shadowsocksr link")
	}
	node.Server = x[0]
	node.Port = x[1]
	node.Protocol = x[2]
	node.Method = x[3]
	node.Obfs = x[4]
	node.Password = Base64d(x[5])
	if len(decodeStr) > 1 {
		query, _ := url.ParseQuery(decodeStr[1])
		node.Group = Base64d(query.Get("group"))
		node.Obfsparam = Base64d(query.Get("obfsparam"))
		node.Protoparam = Base64d(query.Get("protoparam"))
		node.Name = Base64d(query.Get("remarks")) + " - Shadowsocksr"
	}
	return node, nil
}
