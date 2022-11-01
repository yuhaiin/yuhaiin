package register

import (
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	httpc "github.com/Asutorufa/yuhaiin/pkg/net/proxy/http/client"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/quic"
	ss "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocks"
	ssr "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/simple"
	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/trojan"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/vmess"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/websocket"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
)

func init() {
	protocol.RegisterProtocol(func(*protocol.Protocol_None) protocol.WrapProxy {
		return func(p proxy.Proxy) (proxy.Proxy, error) { return p, nil }
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
	protocol.RegisterProtocol(httpc.New)
}

func Dialer(p *point.Point) (r proxy.Proxy, err error) {
	r = direct.Default
	for _, v := range p.Protocols {
		r, err = protocol.Wrap(v.Protocol)(r)
		if err != nil {
			return
		}
	}

	return
}
