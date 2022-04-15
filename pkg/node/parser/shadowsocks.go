package parser

import (
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
)

func init() {
	parseLink.Store(node.NodeLink_shadowsocks, func(data []byte) (*node.Point, error) {
		ssUrl, err := url.Parse(string(data))
		if err != nil {
			return nil, fmt.Errorf("parse url failed: %w", err)
		}

		server, portstr := ssUrl.Hostname(), ssUrl.Port()

		var method, password string
		mps := DecodeUrlBase64(ssUrl.User.String())
		if i := strings.IndexByte(mps, ':'); i != -1 {
			method, password = mps[:i], mps[i+1:]
		}

		var plugin *node.PointProtocol
		pluginopts := parseOpts(ssUrl.Query().Get("plugin"))
		switch {
		case pluginopts["obfs-local"] == "true":
			plugin, err = parseObfs(pluginopts)
		case pluginopts["v2ray"] == "true":
			plugin, err = parseV2ray(pluginopts)
		default:
			plugin = &node.PointProtocol{Protocol: &node.PointProtocol_None{None: &node.None{}}}
		}
		if err != nil {
			return nil, fmt.Errorf("parse plugin failed: %w", err)
		}

		port, err := strconv.Atoi(portstr)
		if err != nil {
			return nil, fmt.Errorf("parse port failed: %w", err)
		}

		return &node.Point{
			Origin: node.Point_remote,
			Name:   "[ss]" + ssUrl.Fragment,
			Protocols: []*node.PointProtocol{
				{
					Protocol: &node.PointProtocol_Simple{
						Simple: &node.Simple{
							Host: server,
							Port: int32(port),
						},
					},
				},
				plugin,
				{
					Protocol: &node.PointProtocol_Shadowsocks{
						Shadowsocks: &node.Shadowsocks{
							Server:   server,
							Port:     portstr,
							Method:   method,
							Password: password,
						},
					},
				},
			},
		}, nil

	})
}

func parseV2ray(store map[string]string) (*node.PointProtocol, error) {
	// fastOpen := false
	// path := "/"
	// host := "cloudfront.com"
	// tlsEnabled := false
	// cert := ""
	// certRaw := ""
	// mode := "websocket"

	var err error
	var cert []byte
	if store["cert"] != "" {
		cert, err = os.ReadFile(store["cert"])
		if err != nil {
			log.Printf("read cert file failed: %v", err)
		}
	}

	ns, _, err := net.SplitHostPort(store["host"])
	if err != nil {
		log.Printf("split host and port failed: %v", err)
		ns = store["host"]
	}

	switch store["mode"] {
	case "websocket":
		return &node.PointProtocol{
			Protocol: &node.PointProtocol_Websocket{
				Websocket: &node.Websocket{
					Host: store["host"],
					Path: store["path"],
					Tls: &node.TlsConfig{
						ServerName: ns,
						Enable:     store["tls"] == "true",
						CaCert:     [][]byte{cert},
					},
				},
			},
		}, nil
	case "quic":
		return &node.PointProtocol{
			Protocol: &node.PointProtocol_Quic{
				Quic: &node.Quic{
					Tls: &node.TlsConfig{
						ServerName: ns,
						CaCert:     [][]byte{cert},
					},
				},
			},
		}, nil
	}

	return nil, fmt.Errorf("unsupported mode: %v", store["mode"])
}

func parseObfs(args map[string]string) (*node.PointProtocol, error) {
	hostname, port, err := net.SplitHostPort(args["obfs-host"])
	if err != nil {
		return nil, err
	}
	return &node.PointProtocol{
		Protocol: &node.PointProtocol_ObfsHttp{
			ObfsHttp: &node.ObfsHttp{
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
