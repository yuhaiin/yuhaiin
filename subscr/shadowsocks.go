package subscr

import (
	"crypto/md5"
	"encoding/hex"
	"net/url"
	"strings"
)

type Shadowsocks struct {
	Type      float64 `json:"type"`
	Server    string  `json:"server"`
	Port      string  `json:"port"`
	Method    string  `json:"method"`
	Password  string  `json:"password"`
	Group     string  `json:"group"`
	Plugin    string  `json:"plugin"`
	PluginOpt string  `json:"plugin_opt"`
	Name      string  `json:"name"`
	Hash      string  `json:"hash"`
}

func ShadowSocksParse(str []byte) (*Shadowsocks, error) {
	n := new(Shadowsocks)
	ssUrl, err := url.Parse(string(str))
	if err != nil {
		return nil, err
	}
	n.Type = shadowsocks
	n.Server = ssUrl.Hostname()
	n.Port = ssUrl.Port()
	n.Method = strings.Split(Base64DStr(ssUrl.User.String()), ":")[0]
	n.Password = strings.Split(Base64DStr(ssUrl.User.String()), ":")[1]
	n.Group = Base64DStr(ssUrl.Query().Get("group"))
	n.Plugin = strings.Split(ssUrl.Query().Get("plugin"), ";")[0]
	n.PluginOpt = strings.Replace(ssUrl.Query().Get("plugin"), n.Plugin+";", "", -1)
	n.Name = "[ss]" + ssUrl.Fragment

	hash := md5.New()
	hash.Write([]byte(n.Server))
	hash.Write([]byte(n.Port))
	hash.Write([]byte(n.Method))
	hash.Write([]byte(n.Password))
	hash.Write([]byte{byte(n.Type)})
	hash.Write([]byte(n.Group))
	hash.Write([]byte(n.Name))
	hash.Write([]byte(n.Plugin))
	hash.Write([]byte(n.PluginOpt))
	n.Hash = hex.EncodeToString(hash.Sum(nil))
	return n, nil
}
