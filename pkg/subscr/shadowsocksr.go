package subscr

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/simple"

	ssrClient "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr"
)

var DefaultShadowsocksr = &shadowsocksr{}

type shadowsocksr struct{}

// ParseLink parse a base64 encode ssr link
func (*shadowsocksr) ParseLink(link []byte, group string) (*Point, error) {
	decodeStr := strings.Split(DecodeUrlBase64(strings.Replace(string(link), "ssr://", "", -1)), "/?")

	p := &Point{
		NOrigin: Point_remote,
		NGroup:  group,
	}

	n := new(Shadowsocksr)
	x := strings.Split(decodeStr[0], ":")
	if len(x) != 6 {
		return nil, errors.New("link: " + decodeStr[0] + " is not format Shadowsocksr link")
	}
	n.Server = x[0]
	n.Port = x[1]
	n.Protocol = x[2]
	n.Method = x[3]
	n.Obfs = x[4]
	n.Password = DecodeUrlBase64(x[5])
	if len(decodeStr) > 1 {
		query, _ := url.ParseQuery(decodeStr[1])
		n.Obfsparam = DecodeUrlBase64(query.Get("obfsparam"))
		n.Protoparam = DecodeUrlBase64(query.Get("protoparam"))
		p.NName = "[ssr]" + DecodeUrlBase64(query.Get("remarks"))
	}
	p.Node = &Point_Shadowsocksr{Shadowsocksr: n}
	z := sha256.Sum256([]byte(p.String()))
	p.NHash = hex.EncodeToString(z[:])

	return p, nil
}

// ParseLinkManual parse a manual base64 encode ssr link
func (r *shadowsocksr) ParseLinkManual(link []byte, group string) (*Point, error) {
	s, err := r.ParseLink(link, group)
	if err != nil {
		return nil, err
	}
	s.NOrigin = Point_manual
	return s, nil
}

// Conn parse to conn function
func (p *Point_Shadowsocksr) Conn() (proxy.Proxy, error) {
	s := p.Shadowsocksr
	if s == nil {
		return nil, fmt.Errorf("value is nil: %v", p)
	}

	ssr, err := ssrClient.NewShadowsocksr(
		s.Server,
		s.Port,
		s.Method,
		s.Password,
		s.Obfs, s.Obfsparam,
		s.Protocol, s.Protoparam,
	)(simple.NewSimple(s.Server, s.Port))
	if err != nil {
		return nil, err
	}
	return ssr, nil
}
