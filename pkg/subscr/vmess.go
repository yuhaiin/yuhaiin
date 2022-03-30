package subscr

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/quic"
	ssClient "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocks"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/simple"
	libVmess "github.com/Asutorufa/yuhaiin/pkg/net/proxy/vmess"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/websocket"
	"google.golang.org/protobuf/encoding/protojson"
)

type vmess struct{}

var DefaultVmess = &vmess{}

//ParseLink parse vmess link
// eg: vmess://eyJob3N0IjoiIiwicGF0aCI6IiIsInRscyI6IiIsInZlcmlmeV9jZXJ0Ijp0cnV
//             lLCJhZGQiOiIxMjcuMC4wLjEiLCJwb3J0IjowLCJhaWQiOjIsIm5ldCI6InRjcC
//             IsInR5cGUiOiJub25lIiwidiI6IjIiLCJwcyI6Im5hbWUiLCJpZCI6ImNjY2MtY
//             2NjYy1kZGRkLWFhYS00NmExYWFhYWFhIiwiY2xhc3MiOjF9Cg
func (*vmess) ParseLink(str []byte) (*Point, error) {
	data := DecodeBase64(strings.ReplaceAll(string(str), "vmess://", ""))
	n := &Vmess{}
	err := protojson.UnmarshalOptions{DiscardUnknown: true, AllowPartial: true}.Unmarshal([]byte(data), n)
	if err != nil {
		z := &Vmess2{}
		err = protojson.UnmarshalOptions{DiscardUnknown: true, AllowPartial: true}.Unmarshal([]byte(data), z)
		if err != nil {
			return nil, fmt.Errorf("unmarshal failed: %v\nstr: -%s-\nRaw: %s", err, data, str)
		}
		n = &Vmess{
			Address:    z.Address,
			Port:       strconv.Itoa(int(z.Port)),
			Uuid:       z.Uuid,
			AlterId:    strconv.Itoa(int(z.AlterId)),
			Ps:         z.Ps,
			Net:        z.Net,
			Type:       z.Type,
			Tls:        z.Tls,
			Host:       z.Host,
			Path:       z.Path,
			V:          z.V,
			VerifyCert: z.VerifyCert,
			Class:      z.Class,
		}

	}

	p := &Point{
		NName:   "[vmess]" + n.Ps,
		NOrigin: Point_remote,
		Node:    &Point_Vmess{Vmess: n},
	}
	z := sha256.Sum256([]byte(p.String()))
	p.NHash = hex.EncodeToString(z[:])
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

//Conn parse map to net.Conn
func (p *Point_Vmess) Conn() (proxy.Proxy, error) {
	x := p.Vmess
	if x == nil {
		return nil, fmt.Errorf("value is nil: %v", p)
	}
	_, err := strconv.ParseUint(x.Port, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("convert port to int failed: %v", err)
	}
	aid, err := strconv.ParseInt(x.AlterId, 10, 0)
	if err != nil {
		return nil, fmt.Errorf("convert AlterId to int failed: %v", err)
	}

	c := simple.NewSimple(x.Address, x.Port)

	pp, err := websocket.NewWebsocket(x.Host, x.Path, !x.VerifyCert, x.Tls == "tls", nil)(c)
	if err != nil {
		return nil, fmt.Errorf("create websocket failed: %w", err)
	}

	pp, err = libVmess.NewVmess(x.Uuid, x.Security, uint32(aid))(pp)
	if err != nil {
		return nil, fmt.Errorf("create vmess failed: %w", err)
	}
	return pp, nil
}

func (p *PointProtocol_Websocket) Conn(z proxy.Proxy) (proxy.Proxy, error) {
	return websocket.NewWebsocket(p.Websocket.Host, p.Websocket.Path,
		p.Websocket.InsecureSkipVerify, p.Websocket.TlsEnable, []string{})(z)
}

func (p *PointProtocol_Quic) Conn(z proxy.Proxy) (proxy.Proxy, error) {
	return quic.NewQUIC(p.Quic.ServerName, []string{}, p.Quic.InsecureSkipVerify)(z)
}

func (p *PointProtocol_ObfsHttp) Conn(z proxy.Proxy) (proxy.Proxy, error) {
	return ssClient.NewHTTPOBFS(p.ObfsHttp.Host, p.ObfsHttp.Port)(z)
}
