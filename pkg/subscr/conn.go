package subscr

import (
	"crypto/tls"
	"fmt"
	"strconv"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/quic"
	ss "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocks"
	ssr "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/simple"
	tc "github.com/Asutorufa/yuhaiin/pkg/net/proxy/trojan"
	vmessc "github.com/Asutorufa/yuhaiin/pkg/net/proxy/vmess"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/websocket"
)

func (p *PointProtocol_Simple) Conn(proxy.Proxy) (proxy.Proxy, error) {
	x := p.Simple
	if x == nil {
		return nil, fmt.Errorf("value is nil: %v", p)
	}

	var tc *tls.Config

	if x.Tls != nil && x.Tls.Enable {
		tc = &tls.Config{
			ServerName:         x.Tls.ServerName,
			InsecureSkipVerify: x.Tls.InsecureSkipVerify,
		}
	}

	return simple.NewSimple(x.Host, strconv.Itoa(int(x.Port)), simple.WithTLS(tc)), nil
}

func (p *PointProtocol_Vmess) Conn(z proxy.Proxy) (proxy.Proxy, error) {
	if p.Vmess == nil {
		return nil, fmt.Errorf("value is nil: %v", p)
	}

	aid, err := strconv.Atoi(p.Vmess.AlterId)
	if err != nil {
		return nil, fmt.Errorf("convert AlterId to int failed: %v", err)
	}
	return vmessc.NewVmess(p.Vmess.Uuid, p.Vmess.Security, uint32(aid))(z)
}

func (p *PointProtocol_Websocket) Conn(z proxy.Proxy) (proxy.Proxy, error) {
	if p.Websocket == nil {
		return nil, fmt.Errorf("value is nil: %v", p)
	}
	return websocket.NewWebsocket(p.Websocket.Host, p.Websocket.Path,
		p.Websocket.InsecureSkipVerify, p.Websocket.TlsEnable, []string{})(z)
}

func (p *PointProtocol_Quic) Conn(z proxy.Proxy) (proxy.Proxy, error) {
	if p.Quic == nil {
		return nil, fmt.Errorf("value is nil: %v", p)
	}
	return quic.NewQUIC(p.Quic.ServerName, []string{}, p.Quic.InsecureSkipVerify)(z)
}

func (p *PointProtocol_ObfsHttp) Conn(z proxy.Proxy) (proxy.Proxy, error) {
	if p.ObfsHttp == nil {
		return nil, fmt.Errorf("value is nil: %v", p)
	}
	return ss.NewHTTPOBFS(p.ObfsHttp.Host, p.ObfsHttp.Port)(z)
}

func (p *PointProtocol_Trojan) Conn(z proxy.Proxy) (proxy.Proxy, error) {
	if p.Trojan == nil {
		return nil, fmt.Errorf("value is nil: %v", p)
	}
	return tc.NewClient(p.Trojan.Password)(z)
}

func (p *PointProtocol_Shadowsocks) Conn(x proxy.Proxy) (proxy.Proxy, error) {
	if p.Shadowsocks == nil {
		return nil, fmt.Errorf("invalid shadowsocks")
	}
	return ss.NewShadowsocks(p.Shadowsocks.Method, p.Shadowsocks.Password,
		p.Shadowsocks.Server, p.Shadowsocks.Port)(x)
}

func (p *PointProtocol_Shadowsocksr) Conn(x proxy.Proxy) (proxy.Proxy, error) {
	s := p.Shadowsocksr
	if s == nil {
		return nil, fmt.Errorf("value is nil: %v", p)
	}

	return ssr.NewShadowsocksr(
		s.Server, s.Port,
		s.Method, s.Password,
		s.Obfs, s.Obfsparam,
		s.Protocol, s.Protoparam)(x)
}

func (p *Point) Conn() (r proxy.Proxy, err error) {
	r = direct.DefaultDirect
	for _, v := range p.Protocols {
		x, ok := v.Protocol.(interface {
			Conn(proxy.Proxy) (proxy.Proxy, error)
		})
		if !ok {
			return nil, fmt.Errorf("protocol %v is not support", v.Protocol)
		}
		r, err = x.Conn(r)
		if err != nil {
			return
		}
	}

	return
}
