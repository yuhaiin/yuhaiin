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

func SsrParse(link []byte) (*Shadowsocksr, error) {
	decodeStr := strings.Split(Base64DStr(strings.Replace(string(link), "ssr://", "", -1)), "/?")
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
	node.Password = Base64DStr(x[5])
	if len(decodeStr) > 1 {
		query, _ := url.ParseQuery(decodeStr[1])
		node.Group = Base64DStr(query.Get("group"))
		node.Obfsparam = Base64DStr(query.Get("obfsparam"))
		node.Protoparam = Base64DStr(query.Get("protoparam"))
		node.Name = "[ssr]" + Base64DStr(query.Get("remarks"))
	}
	return node, nil
}
