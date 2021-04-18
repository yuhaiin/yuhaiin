package vmess

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	"google.golang.org/protobuf/encoding/protojson"

	libVmess "github.com/Asutorufa/yuhaiin/pkg/net/proxy/vmess"
	"github.com/Asutorufa/yuhaiin/pkg/subscr/utils"
)

//ParseLink parse vmess link
// eg: vmess://eyJob3N0IjoiIiwicGF0aCI6IiIsInRscyI6IiIsInZlcmlmeV9jZXJ0Ijp0cnV
//             lLCJhZGQiOiIxMjcuMC4wLjEiLCJwb3J0IjowLCJhaWQiOjIsIm5ldCI6InRjcC
//             IsInR5cGUiOiJub25lIiwidiI6IjIiLCJwcyI6Im5hbWUiLCJpZCI6ImNjY2MtY
//             2NjYy1kZGRkLWFhYS00NmExYWFhYWFhIiwiY2xhc3MiOjF9Cg
func ParseLink(str []byte, group string) (*utils.Point, error) {
	data := utils.DecodeBase64(strings.ReplaceAll(string(str), "vmess://", ""))
	n := &utils.Vmess{}
	err := protojson.UnmarshalOptions{DiscardUnknown: true, AllowPartial: true}.Unmarshal([]byte(data), n)
	if err != nil {
		z := &utils.Vmess2{}
		err = protojson.UnmarshalOptions{DiscardUnknown: true, AllowPartial: true}.Unmarshal([]byte(data), z)
		if err != nil {
			return nil, fmt.Errorf("unmarshal failed: %v\nstr: -%s-\nRaw: %s", err, data, str)
		}
		n = &utils.Vmess{
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

	d, err := protojson.Marshal(n)
	if err != nil {
		return nil, fmt.Errorf("marshal failed: %v", err)
	}

	p := &utils.Point{
		NName:   "[vmess]" + n.Ps,
		NGroup:  group,
		NType:   utils.Point_vmess,
		NOrigin: utils.Point_remote,
		Data:    d,
	}
	z := sha256.Sum256([]byte(p.String()))
	p.NHash = hex.EncodeToString(z[:])
	return p, nil
}

// ParseLinkManual parse a manual base64 encode vmess link
func ParseLinkManual(link []byte, group string) (*utils.Point, error) {
	s, err := ParseLink(link, group)
	if err != nil {
		return nil, err
	}
	s.NOrigin = utils.Point_manual
	return s, nil
}

//ParseConn parse map to net.Conn
func ParseConn(n *utils.Point) (proxy.Proxy, error) {
	x := new(utils.Vmess)
	err := protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(n.Data, x)
	if err != nil {
		return nil, fmt.Errorf("parse vmess map failed: %v", err)
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
		false,
		"",
	)
	if err != nil {
		return nil, fmt.Errorf("new vmess failed: %v", err)
	}

	return v, nil
}
