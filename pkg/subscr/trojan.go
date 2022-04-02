package subscr

import (
	"errors"
	"net/url"
	"strconv"
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
		Name:   "[trojan]" + u.Fragment,
		Origin: Point_remote,
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
