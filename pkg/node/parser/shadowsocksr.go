package parser

import (
	"bytes"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/url"
	"strconv"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/schema/node"
)

func init() {
	store.Store(node.Type_shadowsocksr, func(data []byte) (*node.Point, error) {
		data = bytes.TrimPrefix(data, []byte("ssr://"))
		dst := make([]byte, base64.RawStdEncoding.DecodedLen(len(data)))
		_, err := base64.RawURLEncoding.Decode(dst, data)
		if err != nil {
			log.Warn("parse shadowsocksr failed", slog.String("data", string(data)), slog.Any("err", err))
		}
		// ParseLink parse a base64 encode ssr link
		decodeStr := bytes.Split(dst, []byte{'/', '?'})

		x := strings.Split(string(decodeStr[0]), ":")
		if len(x) != 6 {
			return nil, errors.New("link: " + string(decodeStr[0]) + " is not shadowsocksr link")
		}
		if len(decodeStr) <= 1 {
			decodeStr = append(decodeStr, []byte{})
		}
		query, _ := url.ParseQuery(string(decodeStr[1]))

		port, err := strconv.ParseUint(x[1], 10, 16)
		if err != nil {
			return nil, errors.New("invalid port")
		}

		password, err := base64.RawURLEncoding.DecodeString(x[5])
		if err != nil {
			log.Warn("parse shadowsocksr password failed", "err", err)
		}

		name, _ := base64.RawURLEncoding.DecodeString(query.Get("remarks"))

		obfsparam, _ := base64.RawURLEncoding.DecodeString(query.Get("obfsparam"))
		protoparam, _ := base64.RawURLEncoding.DecodeString(query.Get("protoparam"))
		return node.Point_builder{
			Origin: node.Origin_remote.Enum(),
			Name:   new("[ssr]" + string(name)),
			Protocols: []*node.Protocol{
				node.Protocol_builder{
					Simple: node.Simple_builder{
						Host: new(x[0]),
						Port: new(int32(port)),
					}.Build(),
				}.Build(),

				node.Protocol_builder{
					Shadowsocksr: node.Shadowsocksr_builder{
						Server:     new(x[0]),
						Port:       new(x[1]),
						Protocol:   new(x[2]),
						Method:     new(x[3]),
						Obfs:       new(x[4]),
						Password:   new(string(password)),
						Obfsparam:  new(string(obfsparam)),
						Protoparam: new(string(protoparam)),
					}.Build(),
				}.Build(),
			},
		}.Build(), nil
	})
}
