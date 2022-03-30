package subscr

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/url"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/simple"
	tc "github.com/Asutorufa/yuhaiin/pkg/net/proxy/trojan"
)

var DefaultTrojan = &trojan{}

type trojan struct{}

func (t *trojan) ParseLink(b []byte) (*Point, error) {
	u, err := url.Parse(string(b))
	if err != nil {
	}

	if u.Scheme != "trojan" {
		return nil, errors.New("invalid scheme")
	}

	return &Point{
		NName:   "[trojan]" + u.Fragment,
		NOrigin: Point_remote,
		Node: &Point_Trojan{
			&Trojan{
				Server:   u.Hostname(),
				Port:     u.Port(),
				Password: u.User.String(),
				Sni:      u.Query().Get("sni"),
				Peer:     u.Query().Get("peer"),
			},
		},

		Protocols: []*PointProtocol{},
	}, nil
}

func (p *Point_Trojan) Conn() (proxy.Proxy, error) {
	s := p.Trojan
	if s == nil {
		return nil, fmt.Errorf("value is nil: %v", p)
	}

	return tc.NewClient(s.Password)(
		simple.NewSimple(s.Server, s.Port, simple.WithTLS(&tls.Config{ServerName: s.Sni})),
	)
}
