package register

import (
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/grpc"
	httpproxy "github.com/Asutorufa/yuhaiin/pkg/net/proxy/http"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/http2"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/quic"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/reality"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/reject"
	ss "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocks"
	ssr "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/simple"
	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tls"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/trojan"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/vmess"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/websocket"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
)

func init() {
	protocol.RegisterProtocol(func(*protocol.Protocol_None) protocol.WrapProxy {
		return func(p netapi.Proxy) (netapi.Proxy, error) { return p, nil }
	})
	// simple not wrap conn, it will use system dialer
	protocol.RegisterProtocol(simple.New)
	protocol.RegisterProtocol(vmess.New)
	protocol.RegisterProtocol(websocket.New)
	protocol.RegisterProtocol(quic.New)
	protocol.RegisterProtocol(ss.NewHTTPOBFS)
	protocol.RegisterProtocol(trojan.New)
	protocol.RegisterProtocol(ss.New)
	protocol.RegisterProtocol(ssr.New)
	protocol.RegisterProtocol(s5c.New)
	protocol.RegisterProtocol(httpproxy.NewClient)
	protocol.RegisterProtocol(func(*protocol.Protocol_Direct) protocol.WrapProxy {
		return func(netapi.Proxy) (netapi.Proxy, error) { return direct.Default, nil }
	})
	protocol.RegisterProtocol(func(*protocol.Protocol_Reject) protocol.WrapProxy {
		return func(netapi.Proxy) (netapi.Proxy, error) { return reject.Default, nil }
	})
	protocol.RegisterProtocol(yuubinsya.New)
	protocol.RegisterProtocol(grpc.New)
	protocol.RegisterProtocol(http2.NewClient)
	protocol.RegisterProtocol(reality.NewRealityClient)
	protocol.RegisterProtocol(tls.New)
}

func Dialer(p *point.Point) (r netapi.Proxy, err error) {
	r = direct.Default
	for _, v := range p.Protocols {
		r, err = protocol.Wrap(v.Protocol)(r)
		if err != nil {
			return
		}
	}

	return
}
