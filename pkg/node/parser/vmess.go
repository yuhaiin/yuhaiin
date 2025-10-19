package parser

import (
	"bytes"
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
	"log/slog"
	"net"
	"strconv"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"google.golang.org/protobuf/proto"
)

func init() {
	store.Store(node.Type_vmess, func(data []byte) (*node.Point, error) {
		//ParseLink parse vmess link
		// eg: vmess://eyJob3N0IjoiIiwicGF0aCI6IiIsInRscyI6IiIsInZlcmlmeV9jZXJ0Ijp0cnV
		//             lLCJhZGQiOiIxMjcuMC4wLjEiLCJwb3J0IjowLCJhaWQiOjIsIm5ldCI6InRjcC
		//             IsInR5cGUiOiJub25lIiwidiI6IjIiLCJwcyI6Im5hbWUiLCJpZCI6ImNjY2MtY
		//             2NjYy1kZGRkLWFhYS00NmExYWFhYWFhIiwiY2xhc3MiOjF9Cg

		n := struct {
			Port any `json:"port,omitempty"`
			// alter id
			AlterId any `json:"aid,omitempty"`

			// address
			Address string `json:"add,omitempty"`
			// uuid
			Uuid     string `json:"id,omitempty"`
			Security string `json:"security,omitempty"`

			// name
			Ps     string `json:"ps,omitempty"`
			Remark string `json:"remark,omitempty"`

			// (tcp\kcp\ws\h2\quic)
			Net string `json:"net,omitempty"`

			// fake type [(none\http\srtp\utp\wechat-video) *tcp or kcp or QUIC]
			Type       string `json:"type,omitempty"`
			HeaderType string `json:"headerType,omitempty"`

			Tls string `json:"tls,omitempty"`
			Sni string `json:"sni,omitempty"`

			// 1)http host(cut up with (,) )
			// 2)ws host
			// 3)h2 host
			// 4)QUIC security
			Host string `json:"host,omitempty"`
			// 1)ws path
			// 2)h2 path
			// 3)QUIC key/Kcp seed
			Path string `json:"path,omitempty"`

			V          string `json:"v,omitempty"`
			Class      int64  `json:"class,omitempty"`
			VerifyCert bool   `json:"verify_cert,omitempty"`
		}{}

		data = bytes.TrimRight(bytes.TrimSpace(bytes.TrimPrefix(data, []byte("vmess://"))), "=")
		dst := make([]byte, base64.RawStdEncoding.DecodedLen(len(data)))
		_, err := base64.RawStdEncoding.Decode(dst, data)
		if err != nil {
			log.Warn("base64 decode failed", slog.String("data", string(data)), slog.Any("err", err))
		}
		if err := json.Unmarshal(trimJSON(dst, '{', '}'), &n); err != nil {
			return nil, err
		}

		if n.Ps == "" {
			n.Ps = n.Remark
		}

		if n.Host == "" {
			n.Host = net.JoinHostPort(n.Address, fmt.Sprint(n.Port))
		}

		if n.HeaderType == "" {
			n.HeaderType = n.Type
		}

		port, err := strconv.ParseUint(fmt.Sprint(n.Port), 10, 16)
		if err != nil {
			return nil, fmt.Errorf("vmess port is not a number: %w", err)
		}

		simple := node.Protocol_builder{
			Simple: node.Simple_builder{
				Host: proto.String(n.Address),
				Port: proto.Int32(int32(port)),
			}.Build(),
		}

		tlsProtocol := node.Protocol_builder{None: &node.None{}}.Build()

		if n.Tls == "tls" {
			if n.Sni == "" {
				n.Sni, _, err = net.SplitHostPort(n.Host)
				if err != nil {
					log.Warn("split host and port failed", "err", err)
					n.Sni = n.Host
				}
			}

			tlsProtocol = node.Protocol_builder{
				Tls: node.TlsConfig_builder{
					ServerNames:        []string{n.Sni},
					InsecureSkipVerify: proto.Bool(!n.VerifyCert),
					Enable:             proto.Bool(true),
					CaCert:             nil,
				}.Build(),
			}.Build()
		}

		switch n.HeaderType {
		case "none":
		default:
			return nil, fmt.Errorf("vmess type is not supported: %v", n.Type)
		}

		var netProtocol *node.Protocol
		switch n.Net {
		case "ws":
			netProtocol = node.Protocol_builder{
				Websocket: node.Websocket_builder{
					Host: proto.String(n.Host),
					Path: proto.String(n.Path),
				}.Build(),
			}.Build()
		case "tcp":
			netProtocol = node.Protocol_builder{None: &node.None{}}.Build()
		default:
			return nil, fmt.Errorf("vmess net is not supported: %v", n.Net)
		}

		return node.Point_builder{
			Name:   proto.String("[vmess]" + n.Ps),
			Origin: node.Origin_remote.Enum(),
			Protocols: []*node.Protocol{
				simple.Build(),
				tlsProtocol,
				netProtocol,
				node.Protocol_builder{
					Vmess: node.Vmess_builder{
						Uuid:     proto.String(n.Uuid),
						AlterId:  proto.String(fmt.Sprint(n.AlterId)),
						Security: proto.String(n.Security),
					}.Build(),
				}.Build(),
			},
		}.Build(), nil
	})
}
