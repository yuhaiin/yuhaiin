package parser

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"

	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
)

func init() {
	store.Store(node.NodeLink_trojan, func(data []byte) (*node.Point, error) {
		u, err := url.Parse(string(data))
		if err != nil {
			return nil, fmt.Errorf("parse trojan link error: %w", err)
		}

		if u.Scheme != "trojan" {
			return nil, errors.New("invalid scheme")
		}
		port, err := strconv.Atoi(u.Port())
		if err != nil {
			return nil, errors.New("invalid port")
		}

		p := &node.Point{
			Name:   "[trojan]" + u.Fragment,
			Origin: node.Point_remote,
			Protocols: []*node.PointProtocol{
				{
					Protocol: &node.PointProtocol_Simple{
						Simple: &node.Simple{
							Host: u.Hostname(),
							Port: int32(port),
							Tls: &node.TlsConfig{
								Enable:     true,
								ServerName: u.Query().Get("sni"),
							},
						},
					},
				},
				{
					Protocol: &node.PointProtocol_Trojan{
						Trojan: &node.Trojan{
							Password: u.User.String(),
							Peer:     u.Query().Get("peer"),
						},
					},
				},
			},
		}

		return p, nil
	})
}
