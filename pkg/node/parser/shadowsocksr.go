package parser

import (
	"bytes"
	"errors"
	"net/url"
	"strconv"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
)

func init() {
	store.Store(node.NodeLink_shadowsocksr, func(data []byte) (*node.Point, error) {
		// ParseLink parse a base64 encode ssr link
		decodeStr := bytes.Split(DecodeUrlBase64Bytes(bytes.TrimPrefix(data, []byte("ssr://"))), []byte{'/', '?'})

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

		return &node.Point{
			Origin: node.Point_remote,
			Name:   "[ssr]" + DecodeUrlBase64(query.Get("remarks")),
			Protocols: []*node.PointProtocol{
				{
					Protocol: &node.PointProtocol_Simple{
						Simple: &node.Simple{
							Host: x[0],
							Port: int32(port),
						},
					},
				},
				{
					Protocol: &node.PointProtocol_Shadowsocksr{
						Shadowsocksr: &node.Shadowsocksr{
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
	})
}
