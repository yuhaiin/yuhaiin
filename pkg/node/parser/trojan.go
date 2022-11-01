package parser

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"

	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/subscribe"
)

func init() {
	store.Store(subscribe.Type_trojan, func(data []byte) (*point.Point, error) {
		u, err := url.Parse(string(data))
		if err != nil {
			return nil, fmt.Errorf("parse trojan link error: %w", err)
		}

		if u.Scheme != "trojan" {
			return nil, errors.New("invalid scheme")
		}
		port, err := strconv.ParseUint(u.Port(), 10, 16)
		if err != nil {
			return nil, errors.New("invalid port")
		}

		p := &point.Point{
			Name:   "[trojan]" + u.Fragment,
			Origin: point.Origin_remote,
			Protocols: []*protocol.Protocol{
				{
					Protocol: &protocol.Protocol_Simple{
						Simple: &protocol.Simple{
							Host: u.Hostname(),
							Port: int32(port),
							Tls: &protocol.TlsConfig{
								Enable:     true,
								ServerName: u.Query().Get("sni"),
							},
						},
					},
				},
				{
					Protocol: &protocol.Protocol_Trojan{
						Trojan: &protocol.Trojan{
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
