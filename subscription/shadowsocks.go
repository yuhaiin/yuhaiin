package subscription

import (
	"net/url"
	"strings"
)

type Shadowsocks struct {
	Type     string
	Server   string
	Port     string
	Method   string
	Password string
	Group    string
	Plugin   string
	Name     string
}

func ShadowSocksParse(str []byte) (*Shadowsocks, error) {
	//return base64d.Base64d2(str)
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
	s.Group = Base64d(ssUrl.Query()["group"][0])
	s.Plugin = ssUrl.Query()["plugin"][0]
	s.Name = ssUrl.Fragment
	return s, nil
}
