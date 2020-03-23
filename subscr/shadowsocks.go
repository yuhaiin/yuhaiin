package subscr

import (
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
}

func ShadowSocksParse(str []byte) (*Shadowsocks, error) {
	s := new(Shadowsocks)
	ssUrl, err := url.Parse(string(str))
	if err != nil {
		return nil, err
	}
	s.Type = shadowsocks
	s.Server = ssUrl.Hostname()
	s.Port = ssUrl.Port()
	s.Method = strings.Split(Base64d(ssUrl.User.String()), ":")[0]
	s.Password = strings.Split(Base64d(ssUrl.User.String()), ":")[1]
	s.Group = Base64d(ssUrl.Query().Get("group"))
	s.Plugin = strings.Split(ssUrl.Query().Get("plugin"), ";")[0]
	s.PluginOpt = strings.Replace(ssUrl.Query().Get("plugin"), s.Plugin+";", "", -1)
	s.Name = ssUrl.Fragment + " - Shadowsocks"
	return s, nil
}
