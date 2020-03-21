package subscription

import (
	"net/url"
	"strings"
)

type Shadowsocks struct {
	Type      string
	Server    string
	Port      string
	Method    string
	Password  string
	Group     string
	Plugin    string
	PluginOpt string
	Name      string
}

func ShadowSocksParse(str []byte) (*Shadowsocks, error) {
	s := new(Shadowsocks)
	ssUrl, err := url.Parse(string(str))
	if err != nil {
		return nil, err
	}
	s.Type = ssUrl.Scheme
	s.Server = ssUrl.Hostname()
	s.Port = ssUrl.Port()
	s.Method = strings.Split(Base64d(ssUrl.User.String()), ":")[0]
	s.Password = strings.Split(Base64d(ssUrl.User.String()), ":")[1]
	s.Group = Base64d(ssUrl.Query().Get("group"))
	s.Plugin = strings.Split(ssUrl.Query().Get("plugin"), ";")[0]
	s.PluginOpt = strings.Replace(ssUrl.Query().Get("plugin"), s.Plugin+";", "", -1)
	s.Name = ssUrl.Fragment
	return s, nil
}
