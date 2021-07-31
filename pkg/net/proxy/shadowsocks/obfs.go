package shadowsocks

import (
	"errors"
	"net"
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
		hostname, port, err := net.SplitHostPort(args["obfs-host"])
		if err != nil {
			return nil, err
		}
		return NewHTTPObfs(conn, hostname, port), nil
	default:
		return nil, errors.New("not support plugin")
	}
}
