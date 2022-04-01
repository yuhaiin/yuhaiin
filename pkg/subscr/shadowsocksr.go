package subscr

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"

	ssrClient "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr"
)

var DefaultShadowsocksr = &shadowsocksr{}

type shadowsocksr struct{}

// ParseLink parse a base64 encode ssr link
func (*shadowsocksr) ParseLink(link []byte) (*Point, error) {
	decodeStr := strings.Split(DecodeUrlBase64(strings.TrimPrefix(string(link), "ssr://")), "/?")

	x := strings.Split(decodeStr[0], ":")
	if len(x) != 6 {
		return nil, errors.New("link: " + decodeStr[0] + " is not format Shadowsocksr link")
	}
	if len(decodeStr) <= 1 {
		decodeStr = append(decodeStr, "")
	}
	query, _ := url.ParseQuery(decodeStr[1])

	p := &Point{
		NOrigin: Point_remote,
		NName:   "[ssr]" + DecodeUrlBase64(query.Get("remarks")),
	}

	n := &Shadowsocksr{
		Server:     x[0],
		Port:       x[1],
		Protocol:   x[2],
		Method:     x[3],
		Obfs:       x[4],
		Password:   DecodeUrlBase64(x[5]),
		Obfsparam:  DecodeUrlBase64(query.Get("obfsparam")),
		Protoparam: DecodeUrlBase64(query.Get("protoparam")),
	}

	port, err := strconv.Atoi(n.Port)
	if err != nil {
		return nil, errors.New("invalid port")
	}

	p.Protocols = []*PointProtocol{
		{
			Protocol: &PointProtocol_Simple{
				&Simple{
					Host: n.Server,
					Port: int32(port),
				},
			},
		},
		{
			Protocol: &PointProtocol_Shadowsocksr{n},
		},
	}
	return p, nil
}

// ParseLinkManual parse a manual base64 encode ssr link
func (r *shadowsocksr) ParseLinkManual(link []byte) (*Point, error) {
	s, err := r.ParseLink(link)
	if err != nil {
		return nil, err
	}
	s.NOrigin = Point_manual
	return s, nil
}

func (p *PointProtocol_Shadowsocksr) Conn(x proxy.Proxy) (proxy.Proxy, error) {
	s := p.Shadowsocksr
	if s == nil {
		return nil, fmt.Errorf("value is nil: %v", p)
	}

	ssr, err := ssrClient.NewShadowsocksr(
		s.Server, s.Port,
		s.Method, s.Password,
		s.Obfs, s.Obfsparam,
		s.Protocol, s.Protoparam)(x)
	if err != nil {
		return nil, err
	}
	return ssr, nil
}
