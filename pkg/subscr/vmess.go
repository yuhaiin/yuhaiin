package subscr

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	libVmess "github.com/Asutorufa/yuhaiin/pkg/net/proxy/vmess"
	"google.golang.org/protobuf/encoding/protojson"
)

type vmess struct{}

var DefaultVmess = &vmess{}

//ParseLink parse vmess link
// eg: vmess://eyJob3N0IjoiIiwicGF0aCI6IiIsInRscyI6IiIsInZlcmlmeV9jZXJ0Ijp0cnV
//             lLCJhZGQiOiIxMjcuMC4wLjEiLCJwb3J0IjowLCJhaWQiOjIsIm5ldCI6InRjcC
//             IsInR5cGUiOiJub25lIiwidiI6IjIiLCJwcyI6Im5hbWUiLCJpZCI6ImNjY2MtY
//             2NjYy1kZGRkLWFhYS00NmExYWFhYWFhIiwiY2xhc3MiOjF9Cg
func (*vmess) ParseLink(str []byte, group string) (*Point, error) {
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
		NGroup:  group,
		NOrigin: Point_remote,
		Node:    &Point_Vmess{Vmess: n},
	}
	z := sha256.Sum256([]byte(p.String()))
	p.NHash = hex.EncodeToString(z[:])
	return p, nil
}

// ParseLinkManual parse a manual base64 encode vmess link
func (v *vmess) ParseLinkManual(link []byte, group string) (*Point, error) {
	s, err := v.ParseLink(link, group)
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
	port, err := strconv.Atoi(x.Port)
	if err != nil {
		return nil, fmt.Errorf("convert port to int failed: %v", err)
	}
	aid, err := strconv.Atoi(x.AlterId)
	if err != nil {
		return nil, fmt.Errorf("convert AlterId to int failed: %v", err)
	}

	v, err := libVmess.NewVmess(
		x.Address,
		uint32(port),
		x.Uuid,
		"",
		x.Type,
		uint32(aid),
		x.Net,
		x.Path,
		x.Host,
		x.Tls == "tls",
		!x.VerifyCert,
		"",
	)
	if err != nil {
		return nil, fmt.Errorf("new vmess failed: %v", err)
	}

	return v, nil
}
