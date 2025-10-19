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
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"google.golang.org/protobuf/proto"
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
			Name:   proto.String("[ssr]" + string(name)),
			Protocols: []*node.Protocol{
				node.Protocol_builder{
					Simple: node.Simple_builder{
						Host: proto.String(x[0]),
						Port: proto.Int32(int32(port)),
					}.Build(),
				}.Build(),

				node.Protocol_builder{
					Shadowsocksr: node.Shadowsocksr_builder{
						Server:     proto.String(x[0]),
						Port:       proto.String(x[1]),
						Protocol:   proto.String(x[2]),
						Method:     proto.String(x[3]),
						Obfs:       proto.String(x[4]),
						Password:   proto.String(string(password)),
						Obfsparam:  proto.String(string(obfsparam)),
						Protoparam: proto.String(string(protoparam)),
					}.Build(),
				}.Build(),
			},
		}.Build(), nil
	})
}
