package subscription

import (
	"SsrMicroClient/base64d"
	"net/url"
	"strings"
)

type ShadowSocks struct {
	Type     string
	Server   string
	Port     string
	Method   string
	Password string
	Group    string
	Plugin   string
	Name     string
}

func ShadowSocksParse(str []byte) (*ShadowSocks, error) {
	//return base64d.Base64d2(str)
	s := &ShadowSocks{}
	ssUrl, err := url.Parse(string(str))
	if err != nil {
		return nil, err
	}
	s.Type = ssUrl.Scheme
	s.Server = ssUrl.Hostname()
	s.Port = ssUrl.Port()
	s.Method = strings.Split(base64d.Base64d(ssUrl.User.String()), ":")[0]
	s.Password = strings.Split(base64d.Base64d(ssUrl.User.String()), ":")[1]
	s.Group = base64d.Base64d(ssUrl.Query()["group"][0])
	s.Plugin = ssUrl.Query()["plugin"][0]
	s.Name = ssUrl.Fragment
	return s, nil
}
