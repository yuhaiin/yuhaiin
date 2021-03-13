package shadowsocks

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/Asutorufa/yuhaiin/net/proxy/vmess"
)

func NewV2raySelf(conn net.Conn, options string) (net.Conn, error) {
	// fastOpen := false
	path := "/"
	host := "cloudfront.com"
	tlsEnabled := false
	cert := ""
	// certRaw := ""
	mode := "websocket"

	for _, x := range strings.Split(options, ";") {
		if !strings.Contains(x, "=") {
			if x == "tls" {
				tlsEnabled = true
			}
			continue
		}
		s := strings.Split(x, "=")
		switch s[0] {
		case "mode":
			mode = s[1]
		case "path":
			path = s[1]
		case "cert":
			cert = s[1]
		case "host":
			host = s[1]
			// case "certRaw":
			// certRaw = s[1]
			// case "fastOpen":
			// fastOpen = true
		}
	}

	switch mode {
	case "websocket":
		return vmess.WebsocketDial(conn, host, path, cert, tlsEnabled)
	case "quic":
		u, err := url.Parse("//" + conn.RemoteAddr().String())
		if err != nil {
			return nil, fmt.Errorf("parse [%s] to url failed: %v", conn.RemoteAddr().String(), err)
		}
		port, err := strconv.Atoi(u.Port())
		if err != nil {
			return nil, err
		}
		return vmess.QuicDial(conn.RemoteAddr().Network(), u.Hostname(), port, host, cert)
	}

	return nil, fmt.Errorf("unsupported mode")
}
