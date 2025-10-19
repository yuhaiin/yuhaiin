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
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"google.golang.org/protobuf/proto"
)

func init() {
	store.Store(node.Type_shadowsocks, func(data []byte) (*node.Point, error) {
		ssUrl, err := url.Parse(string(data))
		if err != nil {
			return nil, fmt.Errorf("parse url failed: %w", err)
		}

		server, portstr := ssUrl.Hostname(), ssUrl.Port()

		var method, password string
		mps, err := base64.RawURLEncoding.DecodeString(ssUrl.User.String())
		if err != nil {
			log.Warn("parse shadowsocks user failed", "err", err)
		}
		if i := bytes.IndexByte(mps, ':'); i != -1 {
			method, password = string(mps[:i]), string(mps[i+1:])
		}

		port, err := strconv.ParseUint(portstr, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("parse port failed: %w", err)
		}

		simple := &node.Simple_builder{
			Host: proto.String(server),
			Port: proto.Int32(int32(port)),
		}

		var plugin []*node.Protocol
		pluginopts := parseOpts(ssUrl.Query().Get("plugin"))
		switch {
		case pluginopts["obfs-local"] == "true":
			plugin, err = parseObfs(pluginopts)
		case pluginopts["v2ray"] == "true":
			plugin, err = parseV2ray(pluginopts)
		default:
		}
		if err != nil {
			return nil, fmt.Errorf("parse plugin failed: %w", err)
		}

		protocols := append([]*node.Protocol{
			node.Protocol_builder{
				Simple: simple.Build(),
			}.Build(),
		}, plugin...)

		return (&node.Point_builder{
			Origin: node.Origin_remote.Enum(),
			Name:   proto.String("[ss]" + ssUrl.Fragment),
			Protocols: append(protocols, node.Protocol_builder{
				Shadowsocks: node.Shadowsocks_builder{
					Method:   proto.String(method),
					Password: proto.String(password),
				}.Build(),
			}.Build(),
			),
		}).Build(), nil
	})
}

func parseV2ray(store map[string]string) ([]*node.Protocol, error) {
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
			log.Warn("read cert file failed", "err", err)
		}
	}

	ns, _, err := net.SplitHostPort(store["host"])
	if err != nil {
		log.Warn("split host and port failed", "err", err)
		ns = store["host"]
	}

	switch store["mode"] {
	case "websocket":
		var protocols []*node.Protocol
		protocols = append(protocols, node.Protocol_builder{
			Tls: node.TlsConfig_builder{
				ServerNames: []string{ns},
				Enable:      proto.Bool(store["tls"] == "true"),
				CaCert:      [][]byte{cert},
			}.Build(),
		}.Build())
		return append(protocols, node.Protocol_builder{
			Websocket: node.Websocket_builder{
				Host: proto.String(store["host"]),
				Path: proto.String(store["path"]),
			}.Build(),
		}.Build()), nil
	case "quic":
		return []*node.Protocol{node.Protocol_builder{
			Quic: node.Quic_builder{
				Tls: node.TlsConfig_builder{
					ServerNames: []string{ns},
					CaCert:      [][]byte{cert},
				}.Build(),
			}.Build(),
		}.Build(),
		}, nil
	}

	return nil, fmt.Errorf("unsupported mode: %v", store["mode"])
}

func parseObfs(args map[string]string) ([]*node.Protocol, error) {
	hostname, port, err := net.SplitHostPort(args["obfs-host"])
	if err != nil {
		return nil, err
	}
	return []*node.Protocol{
		node.Protocol_builder{
			ObfsHttp: node.ObfsHttp_builder{
				Host: proto.String(hostname),
				Port: proto.String(port),
			}.Build(),
		}.Build(),
	}, nil
}

func parseOpts(options string) map[string]string {
	store := make(map[string]string)
	for x := range strings.SplitSeq(options, ";") {
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
