package subscr

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

var DefaultShadowsocks = &shadowsocks{}

type shadowsocks struct{}

func (*shadowsocks) ParseLink(str []byte) (*Point, error) {
	n := new(Shadowsocks)
	ssUrl, err := url.Parse(string(str))
	if err != nil {
		return nil, err
	}
	n.Server = ssUrl.Hostname()
	n.Port = ssUrl.Port()
	n.Method = strings.Split(DecodeUrlBase64(ssUrl.User.String()), ":")[0]
	n.Password = strings.Split(DecodeUrlBase64(ssUrl.User.String()), ":")[1]
	n.Plugin = strings.Split(ssUrl.Query().Get("plugin"), ";")[0]
	n.PluginOpt = strings.Replace(ssUrl.Query().Get("plugin"), n.Plugin+";", "", -1)

	p := &Point{
		Origin: Point_remote,
		Name:   "[ss]" + ssUrl.Fragment,
	}

	port, err := strconv.Atoi(n.Port)
	if err != nil {
		return nil, err
	}
	p.Protocols = []*PointProtocol{
		{
			Protocol: &PointProtocol_Simple{
				&Simple{
					Host: n.Server,
					Port: int32(port),
				},
			},
		},
	}

	switch strings.ToLower(n.Plugin) {
	case "obfs-local":
		oh, err := parseObfs(n.PluginOpt)
		if err != nil {
			return nil, err
		}
		p.Protocols = append(p.Protocols, oh)
	case "v2ray":
		v, err := parseV2ray(n.PluginOpt)
		if err != nil {
			return nil, err
		}

		p.Protocols = append(p.Protocols, v)
	default:
	}

	p.Protocols = append(p.Protocols,
		&PointProtocol{Protocol: &PointProtocol_Shadowsocks{
			Shadowsocks: &Shadowsocks{
				Method:   n.Method,
				Password: n.Password,
				Server:   n.Server,
				Port:     n.Port,
			},
		},
		})

	return p, nil
}

func parseV2ray(options string) (*PointProtocol, error) {
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
		return &PointProtocol{
			Protocol: &PointProtocol_Websocket{
				&Websocket{
					Host:      host,
					Path:      path,
					TlsCaCert: cert,
					TlsEnable: tlsEnabled,
				},
			},
		}, nil
	case "quic":
		return &PointProtocol{
			Protocol: &PointProtocol_Quic{
				&Quic{
					ServerName: host,
					TlsCaCert:  cert,
				},
			},
		}, nil
	}

	return nil, fmt.Errorf("unsupported mode")
}

func parseObfs(pluginOpt string) (*PointProtocol, error) {
	args := make(map[string]string)
	for _, x := range strings.Split(pluginOpt, ";") {
		if strings.Contains(x, "=") {
			s := strings.Split(x, "=")
			args[s[0]] = s[1]
		}
	}
	hostname, port, err := net.SplitHostPort(args["obfs-host"])
	if err != nil {
		return nil, err
	}
	return &PointProtocol{
		Protocol: &PointProtocol_ObfsHttp{
			&ObfsHttp{
				Host: hostname,
				Port: port,
			},
		}}, nil

}
