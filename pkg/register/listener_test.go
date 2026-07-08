package register

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/schema/config"
	"github.com/Asutorufa/yuhaiin/pkg/schema/node"
)

func TestGetValue(t *testing.T) {
	i := config.Inbound_builder{
		Socks5: config.Socks5_builder{
			Username: new("123"),
		}.Build(),
		Tcpudp: config.Tcpudp_builder{
			Host: new("123"),
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
