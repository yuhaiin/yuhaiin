package subscr

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
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
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return nil, errors.New("invalid port")
	}

	p := &Point{
		NName:   "[trojan]" + u.Fragment,
		NOrigin: Point_remote,
		Protocols: []*PointProtocol{
			{
				Protocol: &PointProtocol_Simple{
					&Simple{
						Host: u.Hostname(),
						Port: int32(port),
						Tls: &SimpleTlsConfig{
							Enable:     true,
							ServerName: u.Query().Get("sni"),
						},
					},
				},
			},
			{
				Protocol: &PointProtocol_Trojan{
					&Trojan{
						Password: u.User.String(),
						Peer:     u.Query().Get("peer"),
					},
				},
			},
		},
	}

	return p, nil
}

func (p *PointProtocol_Trojan) Conn(z proxy.Proxy) (proxy.Proxy, error) {
	s := p.Trojan
	if s == nil {
		return nil, fmt.Errorf("value is nil: %v", p)
	}

	return tc.NewClient(s.Password)(z)
}
