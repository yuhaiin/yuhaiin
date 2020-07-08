package client

import (
	"errors"
	"net"
	"net/url"
	"strings"
)

var (
	HTTP = "http"
)

func NewObfs(conn net.Conn, pluginOpt string) (net.Conn, error) {
	args := make(map[string]string)
	for _, x := range strings.Split(pluginOpt, ";") {
		if strings.Contains(x, "=") {
			s := strings.Split(x, "=")
			args[s[0]] = s[1]
		}
	}
	switch args["obfs"] {
	case HTTP:
		urlTmp, err := url.Parse("//" + args["obfs-host"])
		if err != nil {
			return nil, err
		}
		return NewHTTPObfs(conn, urlTmp.Hostname(), urlTmp.Port()), nil
	default:
		return nil, errors.New("not support plugin")
	}
}
