package register

import (
	"strconv"

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
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
)

func init() {
	node.RegisterProtocol(func(*node.PointProtocol_None) node.WrapProxy {
		return func(p proxy.Proxy) (proxy.Proxy, error) { return p, nil }
	})
	node.RegisterProtocol(func(p *node.PointProtocol_Simple) node.WrapProxy {
		return func(proxy.Proxy) (proxy.Proxy, error) {
			return simple.NewSimple(p.Simple.Host, strconv.Itoa(int(p.Simple.Port)),
				simple.WithTLS(node.ParseTLSConfig(p.Simple.Tls))), nil
		}
	})
	node.RegisterProtocol(vmess.NewVmess)
	node.RegisterProtocol(websocket.New)
	node.RegisterProtocol(quic.NewQUIC)
	node.RegisterProtocol(ss.NewHTTPOBFS)
	node.RegisterProtocol(trojan.NewClient)
	node.RegisterProtocol(ss.NewShadowsocks)
	node.RegisterProtocol(ssr.NewShadowsocksr)
	node.RegisterProtocol(s5c.NewSocks5)
	node.RegisterProtocol(httpc.NewHttp)
}

func Dialer(p *node.Point) (r proxy.Proxy, err error) {
	r = direct.Default
	for _, v := range p.Protocols {
		r, err = node.Wrap(v.Protocol)(r)
		if err != nil {
			return
		}
	}

	return
}
