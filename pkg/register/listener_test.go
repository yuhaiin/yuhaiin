package register

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestRangeFields(t *testing.T) {
	i := &listener.Inbound{}

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

	ta := *new(*listener.Socks4A)

	t.Log(ta.ProtoReflect().Descriptor().FullName(), ta.ProtoReflect().Descriptor().Parent().Name())
}

func TestGetValue(t *testing.T) {
	i := listener.Inbound_builder{
		Socks5: listener.Socks5_builder{
			Username: proto.String("123"),
		}.Build(),
		Tcpudp: listener.Tcpudp_builder{
			Host: proto.String("123"),
		}.Build(),
	}.Build()

	t.Log(GetProtocolOneofValue(i))
	t.Log(GetNetworkOneofValue(i))

	tt := listener.Transport_builder{
		Tls: listener.Tls_builder{
			Tls: protocol.TlsServerConfig_builder{
				NextProtos: []string{"123"},
			}.Build(),
		}.Build(),
	}.Build()

	t.Log(GetTransportOneofValue(tt))
}
