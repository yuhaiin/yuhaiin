package parser

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	sysnet "net"
	"strconv"

	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
)

func init() {
	var get func(interface{}) string
	var trim func([]byte) []byte

	store.Store(node.NodeLink_vmess, func(data []byte) (*node.Point, error) {
		//ParseLink parse vmess link
		// eg: vmess://eyJob3N0IjoiIiwicGF0aCI6IiIsInRscyI6IiIsInZlcmlmeV9jZXJ0Ijp0cnV
		//             lLCJhZGQiOiIxMjcuMC4wLjEiLCJwb3J0IjowLCJhaWQiOjIsIm5ldCI6InRjcC
		//             IsInR5cGUiOiJub25lIiwidiI6IjIiLCJwcyI6Im5hbWUiLCJpZCI6ImNjY2MtY
		//             2NjYy1kZGRkLWFhYS00NmExYWFhYWFhIiwiY2xhc3MiOjF9Cg
		if get == nil {
			get = func(p interface{}) string {
				switch p := p.(type) {
				case string:
					return p
				case float64:
					return strconv.Itoa(int(p))
				}

				return ""
			}
		}

		if trim == nil {
			trim = func(b []byte) []byte { return trimJSON(b, '{', '}') }
		}

		n := struct {
			// address
			Address string      `json:"add,omitempty"`
			Port    interface{} `json:"port,omitempty"`
			// uuid
			Uuid string `json:"id,omitempty"`
			// alter id
			AlterId interface{} `json:"aid,omitempty"`
			// name
			Ps string `json:"ps,omitempty"`
			// (tcp\kcp\ws\h2\quic)
			Net string `json:"net,omitempty"`
			// fake type [(none\http\srtp\utp\wechat-video) *tcp or kcp or QUIC]
			Type string `json:"type,omitempty"`
			Tls  string `json:"tls,omitempty"`
			// 1)http host(cut up with (,) )
			// 2)ws host
			// 3)h2 host
			// 4)QUIC security
			Host string `json:"host,omitempty"`
			// 1)ws path
			// 2)h2 path
			// 3)QUIC key/Kcp seed
			Path       string `json:"path,omitempty"`
			V          string `json:"v,omitempty"`
			VerifyCert bool   `json:"verify_cert,omitempty"`
			Class      int64  `json:"class,omitempty"`
			Security   string `json:"security,omitempty"`
		}{}
		err := json.Unmarshal(trim(DecodeBase64Bytes(bytes.TrimPrefix(data, []byte("vmess://")))), &n)
		if err != nil {
			return nil, err
		}

		port, err := strconv.Atoi(get(n.Port))
		if err != nil {
			return nil, fmt.Errorf("vmess port is not a number: %v", err)
		}

		switch n.Type {
		case "none":
		default:
			return nil, fmt.Errorf("vmess type is not supported: %v", n.Type)
		}

		var net *node.PointProtocol
		switch n.Net {
		case "ws":
			ns, _, err := sysnet.SplitHostPort(n.Host)
			if err != nil {
				log.Printf("split host and port failed: %v", err)
				ns = n.Host
			}

			net = &node.PointProtocol{
				Protocol: &node.PointProtocol_Websocket{
					Websocket: &node.Websocket{
						Host: n.Host,
						Path: n.Path,
						Tls: &node.TlsConfig{
							ServerName:         ns,
							InsecureSkipVerify: !n.VerifyCert,
							Enable:             n.Tls == "tls",
							CaCert:             nil,
						},
					},
				},
			}
		case "tcp":
			net = &node.PointProtocol{Protocol: &node.PointProtocol_None{None: &node.None{}}}
		default:
			return nil, fmt.Errorf("vmess net is not supported: %v", n.Net)
		}

		return &node.Point{
			Name:   "[vmess]" + n.Ps,
			Origin: node.Point_remote,
			Protocols: []*node.PointProtocol{
				{
					Protocol: &node.PointProtocol_Simple{
						Simple: &node.Simple{
							Host: n.Address,
							Port: int32(port),
						},
					},
				},
				net,
				{
					Protocol: &node.PointProtocol_Vmess{
						Vmess: &node.Vmess{
							Uuid:     n.Uuid,
							AlterId:  get(n.AlterId),
							Security: n.Security,
						},
					},
				},
			},
		}, nil
	})
}

func trimJSON(b []byte, start, end byte) []byte {
	s := bytes.IndexByte(b, start)
	e := bytes.LastIndexByte(b, end)
	if s == -1 || e == -1 {
		return b
	}
	return b[s : e+1]
}
