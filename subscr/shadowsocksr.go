package subscr

import (
	"crypto/md5"
	"encoding/hex"
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
	Hash       string  `json:"hash"`
}

func SsrParse(link []byte) (*Shadowsocksr, error) {
	decodeStr := strings.Split(Base64DStr(strings.Replace(string(link), "ssr://", "", -1)), "/?")
	n := new(Shadowsocksr)
	n.Type = shadowsocksr
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
		n.Group = Base64DStr(query.Get("group"))
		n.Obfsparam = Base64DStr(query.Get("obfsparam"))
		n.Protoparam = Base64DStr(query.Get("protoparam"))
		n.Name = "[ssr]" + Base64DStr(query.Get("remarks"))
	}

	hash := md5.New()
	hash.Write([]byte(n.Server))
	hash.Write([]byte(n.Port))
	hash.Write([]byte(n.Method))
	hash.Write([]byte(n.Password))
	hash.Write([]byte{byte(n.Type)})
	hash.Write([]byte(n.Group))
	hash.Write([]byte(n.Name))
	hash.Write([]byte(n.Obfs))
	hash.Write([]byte(n.Obfsparam))
	hash.Write([]byte(n.Protocol))
	hash.Write([]byte(n.Protoparam))
	n.Hash = hex.EncodeToString(hash.Sum(nil))
	return n, nil
}
