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
	ssUrl, err := url.Parse(string(str))
	if err != nil {
		return nil, fmt.Errorf("parse url failed: %w", err)
	}

	server, portstr := ssUrl.Hostname(), ssUrl.Port()

	var method, password string
	mps := DecodeUrlBase64(ssUrl.User.String())
	if i := strings.IndexByte(mps, ':'); i != -1 {
		method, password = mps[:i], mps[i+1:]
	}

	var plugin *PointProtocol
	pluginopts := parseOpts(ssUrl.Query().Get("plugin"))
	switch {
	case pluginopts["obfs-local"] == "true":
		plugin, err = parseObfs(pluginopts)
	case pluginopts["v2ray"] == "true":
		plugin, err = parseV2ray(pluginopts)
	default:
		plugin = &PointProtocol{Protocol: &PointProtocol_None{&None{}}}
	}
	if err != nil {
		return nil, fmt.Errorf("parse plugin failed: %w", err)
	}

	port, err := strconv.Atoi(portstr)
	if err != nil {
		return nil, fmt.Errorf("parse port failed: %w", err)
	}

	return &Point{
		Origin: Point_remote,
		Name:   "[ss]" + ssUrl.Fragment,
		Protocols: []*PointProtocol{
			{
				Protocol: &PointProtocol_Simple{
					&Simple{
						Host: server,
						Port: int32(port),
					},
				},
			},
			plugin,
			{
				Protocol: &PointProtocol_Shadowsocks{
					&Shadowsocks{
						Server:   server,
						Port:     portstr,
						Method:   method,
						Password: password,
					},
				},
			},
		},
	}, nil
}

func parseV2ray(store map[string]string) (*PointProtocol, error) {
	// fastOpen := false
	// path := "/"
	// host := "cloudfront.com"
	// tlsEnabled := false
	// cert := ""
	// certRaw := ""
	// mode := "websocket"

	switch store["mode"] {
	case "websocket":
		return &PointProtocol{
			Protocol: &PointProtocol_Websocket{
				&Websocket{
					Host:      store["host"],
					Path:      store["path"],
					TlsCaCert: store["cert"],
					TlsEnable: store["tls"] == "true",
				},
			},
		}, nil
	case "quic":
		return &PointProtocol{
			Protocol: &PointProtocol_Quic{
				&Quic{
					ServerName: store["host"],
					TlsCaCert:  store["cert"],
				},
			},
		}, nil
	}

	return nil, fmt.Errorf("unsupported mode: %v", store["mode"])
}

func parseObfs(args map[string]string) (*PointProtocol, error) {
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
		},
	}, nil

}

func parseOpts(options string) map[string]string {
	store := make(map[string]string)
	for _, x := range strings.Split(options, ";") {
		i := strings.IndexByte(x, '=')
		if i == -1 {
			store[x] = "true"
		} else {
			key, value := x[:i], x[i+1:]
			store[key] = value
		}
	}
	return store
}
