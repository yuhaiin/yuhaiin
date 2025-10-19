package register

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestRangeFields(t *testing.T) {
	i := &config.Inbound{}

	fields := i.ProtoReflect().Descriptor().Fields()

	oneOfMap := map[protoreflect.Name][]protoreflect.Name{}
	for i := range fields.Len() {
		x := fields.Get(i)
		// t.Log(x.FullName())
		oneof := x.ContainingOneof()
		if oneof == nil {
			continue
		}

		_, ok := oneOfMap[oneof.Name()]
		if ok {
			continue
		}

		resp := []protoreflect.Name{}
		ofds := oneof.Fields()

		for j := range ofds.Len() {
			y := ofds.Get(j)
			resp = append(resp, y.Name())
		}

		oneOfMap[oneof.Name()] = resp
	}

	t.Log(oneOfMap)

	ta := *new(*config.Socks4A)

	t.Log(ta.ProtoReflect().Descriptor().FullName(), ta.ProtoReflect().Descriptor().Parent().Name())
}

func TestGetValue(t *testing.T) {
	i := config.Inbound_builder{
		Socks5: config.Socks5_builder{
			Username: proto.String("123"),
		}.Build(),
		Tcpudp: config.Tcpudp_builder{
			Host: proto.String("123"),
		}.Build(),
	}.Build()

	t.Log(GetProtocolOneofValue(i))
	t.Log(GetNetworkOneofValue(i))

	tt := config.Transport_builder{
		Tls: config.Tls_builder{
			Tls: node.TlsServerConfig_builder{
				NextProtos: []string{"123"},
			}.Build(),
		}.Build(),
	}.Build()

	t.Log(GetTransportOneofValue(tt))
}
