package register

import (
	"crypto/rand"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"google.golang.org/protobuf/proto"
)

func ConvertTransport(x *listener.Transport) (*protocol.Protocol, error) {
	var pro *protocol.Protocol
	switch x.WhichTransport() {
	case listener.Transport_Tls_case:
		pro = protocol.Protocol_builder{
			Tls: protocol.TlsConfig_builder{
				Enable:      proto.Bool(true),
				NextProtos:  x.GetTls().GetTls().GetNextProtos(),
				ServerNames: []string{},
			}.Build(),
		}.Build()
	case listener.Transport_TlsAuto_case:
		pro = protocol.Protocol_builder{
			Tls: protocol.TlsConfig_builder{
				Enable:      proto.Bool(true),
				NextProtos:  x.GetTlsAuto().GetNextProtos(),
				ServerNames: replacePatternServernames(x.GetTlsAuto().GetServernames()),
				CaCert:      [][]byte{x.GetTlsAuto().GetCaCert()},
				EchConfig:   x.GetTlsAuto().GetEch().GetConfig(),
			}.Build(),
		}.Build()
	case listener.Transport_Grpc_case:
		pro = protocol.Protocol_builder{
			Grpc: protocol.Grpc_builder{
				Tls: protocol.TlsConfig_builder{}.Build(),
			}.Build(),
		}.Build()
	}

	return pro, nil
}

func replacePatternServernames(servernames []string) []string {
	var resp []string

	for _, v := range servernames {
		if len(v) == 0 {
			continue
		}

		if v[0] == '*' {
			resp = append(resp, rand.Text()+v[1:])
		} else {
			resp = append(resp, v)
		}
	}

	return resp
}
