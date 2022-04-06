package subscr

import (
	"bytes"
	"errors"
	"net/url"
	"strconv"
	"strings"
)

var DefaultShadowsocksr = &shadowsocksr{}

type shadowsocksr struct{}

// ParseLink parse a base64 encode ssr link
func (*shadowsocksr) ParseLink(link []byte) (*Point, error) {
	decodeStr := bytes.Split(DecodeUrlBase64Bytes(bytes.TrimPrefix(link, []byte("ssr://"))), []byte{'/', '?'})

	x := strings.Split(string(decodeStr[0]), ":")
	if len(x) != 6 {
		return nil, errors.New("link: " + string(decodeStr[0]) + " is not shadowsocksr link")
	}
	if len(decodeStr) <= 1 {
		decodeStr = append(decodeStr, []byte{})
	}
	query, _ := url.ParseQuery(string(decodeStr[1]))

	port, err := strconv.Atoi(x[1])
	if err != nil {
		return nil, errors.New("invalid port")
	}

	return &Point{
		Origin: Point_remote,
		Name:   "[ssr]" + DecodeUrlBase64(query.Get("remarks")),
		Protocols: []*PointProtocol{
			{
				Protocol: &PointProtocol_Simple{
					&Simple{
						Host: x[0],
						Port: int32(port),
					},
				},
			},
			{
				Protocol: &PointProtocol_Shadowsocksr{
					Shadowsocksr: &Shadowsocksr{
						Server:     x[0],
						Port:       x[1],
						Protocol:   x[2],
						Method:     x[3],
						Obfs:       x[4],
						Password:   DecodeUrlBase64(x[5]),
						Obfsparam:  DecodeUrlBase64(query.Get("obfsparam")),
						Protoparam: DecodeUrlBase64(query.Get("protoparam")),
					},
				},
			},
		},
	}, nil
}

// ParseLinkManual parse a manual base64 encode ssr link
func (r *shadowsocksr) ParseLinkManual(link []byte) (*Point, error) {
	s, err := r.ParseLink(link)
	if err != nil {
		return nil, err
	}
	s.Origin = Point_manual
	return s, nil
}
