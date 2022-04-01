package subscr

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/quic"
	ss "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocks"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/simple"
	vmessc "github.com/Asutorufa/yuhaiin/pkg/net/proxy/vmess"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/websocket"
)

type vmess struct{}

var DefaultVmess = &vmess{}

//ParseLink parse vmess link
// eg: vmess://eyJob3N0IjoiIiwicGF0aCI6IiIsInRscyI6IiIsInZlcmlmeV9jZXJ0Ijp0cnV
//             lLCJhZGQiOiIxMjcuMC4wLjEiLCJwb3J0IjowLCJhaWQiOjIsIm5ldCI6InRjcC
//             IsInR5cGUiOiJub25lIiwidiI6IjIiLCJwcyI6Im5hbWUiLCJpZCI6ImNjY2MtY
//             2NjYy1kZGRkLWFhYS00NmExYWFhYWFhIiwiY2xhc3MiOjF9Cg
func (*vmess) ParseLink(str []byte) (*Point, error) {
	data := DecodeBase64(strings.TrimPrefix(string(str), "vmess://"))
	n := struct {
		// address
		Address string `json:"add,omitempty"`
		Port    string `json:"port,omitempty"`
		// uuid
		Uuid string `json:"id,omitempty"`
		// alter id
		AlterId string `json:"aid,omitempty"`
		// name
		Ps string `json:"ps,omitempty"`
		// (tcp\kcp\ws\h2\quic)
		Net string `json:"net,omitempty"`
		// fake type [(none\http\srtp\utp\wechat-video) *tcp or kcp or QUIC]
		Type string `json:"type,omitempty"`
		Tls  string `json:"tls,omitempty"`
		// 1)http host(cut up with (,) )
		// 2)ws host
		// 3)h2 host
		// 4)QUIC security
		Host string `json:"host,omitempty"`
		// 1)ws path
		// 2)h2 path
		// 3)QUIC key/Kcp seed
		Path       string `json:"path,omitempty"`
		V          string `json:"v,omitempty"`
		VerifyCert bool   `json:"verify_cert,omitempty"`
		Class      int64  `json:"class,omitempty"`
		Security   string `json:"security,omitempty"`
	}{}
	err := json.Unmarshal([]byte(data), &n)
	if err != nil {
		z := struct {
			// address
			Address string `json:"add,omitempty"`
			Port    int32  `json:"port,omitempty"`
			// uuid
			Uuid string `json:"id,omitempty"`
			// alter id
			AlterId int32 `json:"aid,omitempty"`
			// name
			Ps string `json:"ps,omitempty"`
			// (tcp\kcp\ws\h2\quic)
			Net string `json:"net,omitempty"`
			// fake type [(none\http\srtp\utp\wechat-video) *tcp or kcp or QUIC]
			Type string `json:"type,omitempty"`
			Tls  string `json:"tls,omitempty"`
			// 1)http host(cut up with (,) )
			// 2)ws host
			// 3)h2 host
			// 4)QUIC security
			Host string `json:"host,omitempty"`
			// 1)ws path
			// 2)h2 path
			// 3)QUIC key/Kcp seed
			Path       string `json:"path,omitempty"`
			V          string `json:"v,omitempty"`
			VerifyCert bool   `json:"verify_cert,omitempty"`
			Class      int64  `json:"class,omitempty"`
			Security   string `json:"security,omitempty"`
		}{}
		err = json.Unmarshal([]byte(data), &z)
		if err != nil {
			return nil, fmt.Errorf("unmarshal failed: %v\nstr: -%s-\nRaw: %s", err, data, str)
		}
		n.Address = z.Address
		n.Port = strconv.Itoa(int(z.Port))
		n.Uuid = z.Uuid
		n.AlterId = strconv.Itoa(int(z.AlterId))
		n.Ps = z.Ps
		n.Net = z.Net
		n.Type = z.Type
		n.Tls = z.Tls
		n.Host = z.Host
		n.Path = z.Path
		n.V = z.V
		n.VerifyCert = z.VerifyCert
		n.Class = z.Class
		n.Security = z.Security
	}

	p := &Point{
		NName:   "[vmess]" + n.Ps,
		NOrigin: Point_remote,
	}

	port, err := strconv.Atoi(n.Port)
	if err != nil {
		return nil, fmt.Errorf("vmess port is not a number: %v", err)
	}
	p.Protocols = []*PointProtocol{
		{
			Protocol: &PointProtocol_Simple{
				&Simple{
					Host: n.Address,
					Port: int32(port),
				},
			},
		},
	}

	switch n.Type {
	case "none":
	default:
		return nil, fmt.Errorf("vmess type is not supported: %v", n.Type)
	}

	switch n.Net {
	case "tcp":
	case "ws":
		p.Protocols = append(p.Protocols, &PointProtocol{
			Protocol: &PointProtocol_Websocket{
				&Websocket{
					Host:               n.Host,
					Path:               n.Path,
					InsecureSkipVerify: !n.VerifyCert,
					TlsEnable:          n.Tls == "tls",
					TlsCaCert:          "",
				},
			},
		})
	default:
		return nil, fmt.Errorf("vmess net is not supported: %v", n.Net)
	}

	p.Protocols = append(p.Protocols, &PointProtocol{
		Protocol: &PointProtocol_Vmess{
			&Vmess{
				Uuid:     n.Uuid,
				AlterId:  n.AlterId,
				Security: n.Security,
			},
		},
	})
	return p, nil
}

// ParseLinkManual parse a manual base64 encode vmess link
func (v *vmess) ParseLinkManual(link []byte) (*Point, error) {
	s, err := v.ParseLink(link)
	if err != nil {
		return nil, err
	}
	s.NOrigin = Point_manual
	return s, nil
}

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
	aid, err := strconv.Atoi(p.Vmess.AlterId)
	if err != nil {
		return nil, fmt.Errorf("convert AlterId to int failed: %v", err)
	}
	return vmessc.NewVmess(p.Vmess.Uuid, p.Vmess.Security, uint32(aid))(z)
}

func (p *PointProtocol_Websocket) Conn(z proxy.Proxy) (proxy.Proxy, error) {
	return websocket.NewWebsocket(p.Websocket.Host, p.Websocket.Path,
		p.Websocket.InsecureSkipVerify, p.Websocket.TlsEnable, []string{})(z)
}

func (p *PointProtocol_Quic) Conn(z proxy.Proxy) (proxy.Proxy, error) {
	return quic.NewQUIC(p.Quic.ServerName, []string{}, p.Quic.InsecureSkipVerify)(z)
}

func (p *PointProtocol_ObfsHttp) Conn(z proxy.Proxy) (proxy.Proxy, error) {
	return ss.NewHTTPOBFS(p.ObfsHttp.Host, p.ObfsHttp.Port)(z)
}
