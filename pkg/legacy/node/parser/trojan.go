package parser

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"

	"github.com/Asutorufa/yuhaiin/pkg/legacy/schema/node"
)

func init() {
	store.Store(node.Type_trojan, func(data []byte) (*node.Point, error) {
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

		var servername []string
		if u.Query().Get("sni") != "" {
			servername = []string{u.Query().Get("sni")}
		}

		p := node.Point_builder{
			Name:   new("[trojan]" + u.Fragment),
			Origin: node.Origin_remote.Enum(),
			Protocols: []*node.Protocol{
				node.Protocol_builder{
					Simple: node.Simple_builder{
						Host: new(u.Hostname()),
						Port: new(int32(port)),
					}.Build(),
				}.Build(),
				node.Protocol_builder{
					Tls: node.TlsConfig_builder{
						Enable:      new(true),
						ServerNames: servername,
					}.Build(),
				}.Build(),
				node.Protocol_builder{
					Trojan: node.Trojan_builder{
						Password: new(u.User.String()),
						Peer:     new(u.Query().Get("peer")),
					}.Build(),
				}.Build(),
			},
		}

		return p.Build(), nil
	})
}
