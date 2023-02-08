package parser

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/subscribe"
)

func init() {
	store.Store(subscribe.Type_shadowsocks, func(data []byte) (*point.Point, error) {
		ssUrl, err := url.Parse(string(data))
		if err != nil {
			return nil, fmt.Errorf("parse url failed: %w", err)
		}

		server, portstr := ssUrl.Hostname(), ssUrl.Port()

		var method, password string
		mps, err := base64.RawURLEncoding.DecodeString(ssUrl.User.String())
		if err != nil {
			log.Warningf("parse shadowsocks user failed: %v", err)
		}
		if i := bytes.IndexByte(mps, ':'); i != -1 {
			method, password = string(mps[:i]), string(mps[i+1:])
		}

		port, err := strconv.ParseUint(portstr, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("parse port failed: %w", err)
		}

		simple := &protocol.Simple{
			Host: server,
			Port: int32(port),
		}

		var plugin *protocol.Protocol
		pluginopts := parseOpts(ssUrl.Query().Get("plugin"))
		switch {
		case pluginopts["obfs-local"] == "true":
			plugin, err = parseObfs(pluginopts)
		case pluginopts["v2ray"] == "true":
			plugin, err = parseV2ray(pluginopts, simple)
		default:
			plugin = &protocol.Protocol{Protocol: &protocol.Protocol_None{None: &protocol.None{}}}
		}
		if err != nil {
			return nil, fmt.Errorf("parse plugin failed: %w", err)
		}

		return &point.Point{
			Origin: point.Origin_remote,
			Name:   "[ss]" + ssUrl.Fragment,
			Protocols: []*protocol.Protocol{
				{
					Protocol: &protocol.Protocol_Simple{
						Simple: simple,
					},
				},
				plugin,
				{
					Protocol: &protocol.Protocol_Shadowsocks{
						Shadowsocks: &protocol.Shadowsocks{
							Method:   method,
							Password: password,
						},
					},
				},
			},
		}, nil

	})
}

func parseV2ray(store map[string]string, simple *protocol.Simple) (*protocol.Protocol, error) {
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
			log.Warningf("read cert file failed: %v", err)
		}
	}

	ns, _, err := net.SplitHostPort(store["host"])
	if err != nil {
		log.Warningf("split host and port failed: %v", err)
		ns = store["host"]
	}

	switch store["mode"] {
	case "websocket":
		if store["tls"] == "true" {
			simple.Tls = &protocol.TlsConfig{
				ServerName: ns,
				Enable:     store["tls"] == "true",
				CaCert:     [][]byte{cert},
			}
		}
		return &protocol.Protocol{
			Protocol: &protocol.Protocol_Websocket{
				Websocket: &protocol.Websocket{
					Host:       store["host"],
					Path:       store["path"],
					TlsEnabled: simple.Tls != nil,
				},
			},
		}, nil
	case "quic":
		return &protocol.Protocol{
			Protocol: &protocol.Protocol_Quic{
				Quic: &protocol.Quic{
					Tls: &protocol.TlsConfig{
						ServerName: ns,
						CaCert:     [][]byte{cert},
					},
				},
			},
		}, nil
	}

	return nil, fmt.Errorf("unsupported mode: %v", store["mode"])
}

func parseObfs(args map[string]string) (*protocol.Protocol, error) {
	hostname, port, err := net.SplitHostPort(args["obfs-host"])
	if err != nil {
		return nil, err
	}
	return &protocol.Protocol{
		Protocol: &protocol.Protocol_ObfsHttp{
			ObfsHttp: &protocol.ObfsHttp{
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
