package parser

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"

	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/subscribe"
	"google.golang.org/protobuf/proto"
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

		var servername []string
		if u.Query().Get("sni") != "" {
			servername = []string{u.Query().Get("sni")}
		}

		p := point.Point_builder{
			Name:   proto.String("[trojan]" + u.Fragment),
			Origin: point.Origin_remote.Enum(),
			Protocols: []*protocol.Protocol{
				protocol.Protocol_builder{
					Simple: protocol.Simple_builder{
						Host: proto.String(u.Hostname()),
						Port: proto.Int32(int32(port)),
					}.Build(),
				}.Build(),
				protocol.Protocol_builder{
					Tls: protocol.TlsConfig_builder{
						Enable:      proto.Bool(true),
						ServerNames: servername,
					}.Build(),
				}.Build(),
				protocol.Protocol_builder{
					Trojan: protocol.Trojan_builder{
						Password: proto.String(u.User.String()),
						Peer:     proto.String(u.Query().Get("peer")),
					}.Build(),
				}.Build(),
			},
		}

		return p.Build(), nil
	})
}
