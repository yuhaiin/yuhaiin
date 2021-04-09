package vmess

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"

	netUtils "github.com/Asutorufa/yuhaiin/pkg/net/utils"

	libVmess "github.com/Asutorufa/yuhaiin/pkg/net/proxy/vmess"
	"github.com/Asutorufa/yuhaiin/pkg/subscr/utils"
)

//Vmess vmess
type Vmess struct {
	utils.NodeMessage
	JSON
}

//JSON vmess json from remote
type JSON struct {
	Address string `json:"add"` // address
	Port    uint32 `json:"port"`
	UUID    string `json:"id"`   // uuid
	AlterID uint32 `json:"aid"`  // alter id
	Ps      string `json:"ps"`   // name
	Net     string `json:"net"`  // (tcp\kcp\ws\h2\quic)
	Type    string `json:"type"` // fake type [(none\http\srtp\utp\wechat-video) *tcp or kcp or QUIC]
	TLS     string `json:"tls"`

	Host string `json:"host"`
	// 1)http host(cut up with (,) )
	// 2)ws host
	// 3)h2 host
	// 4)QUIC security
	Path string `json:"path"`
	// 1)ws path
	// 2)h2 path
	// 3)QUIC key/Kcp seed

	V          string `json:"v"`
	VerifyCert bool   `json:"verify_cert"`
	Class      int    `json:"class"`
}

//ParseLink parse vmess link
// eg: vmess://eyJob3N0IjoiIiwicGF0aCI6IiIsInRscyI6IiIsInZlcmlmeV9jZXJ0Ijp0cnV
//             lLCJhZGQiOiIxMjcuMC4wLjEiLCJwb3J0IjowLCJhaWQiOjIsIm5ldCI6InRjcC
//             IsInR5cGUiOiJub25lIiwidiI6IjIiLCJwcyI6Im5hbWUiLCJpZCI6ImNjY2MtY
//             2NjYy1kZGRkLWFhYS00NmExYWFhYWFhIiwiY2xhc3MiOjF9Cg
func ParseLink(str []byte, group string) (*utils.Point, error) {
	s := string(str)
	s = strings.ReplaceAll(s, "vmess://", "")
	data := utils.Base64DStr(s)

	vmess, err := unmarshalJSON([]byte(data))
	if err != nil {
		return nil, fmt.Errorf("unmarshal failed: %v\nstr: %s\nRaw: %s", err, data, str)
	}

	n := &Vmess{
		NodeMessage: utils.NodeMessage{
			NName:   "[vmess]" + vmess.Ps,
			NGroup:  group,
			NType:   utils.Vmess,
			NOrigin: utils.Remote,
		},
		JSON: *vmess,
	}
	n.NHash = countHash(n, string(data))

	dat, err := json.Marshal(n)
	if err != nil {
		return nil, fmt.Errorf("vmess marshal failed: %v", err)
	}
	return &utils.Point{
		NodeMessage: n.NodeMessage,
		Data:        dat,
	}, nil
}

// ParseLinkManual parse a manual base64 encode vmess link
func ParseLinkManual(link []byte, group string) (*utils.Point, error) {
	s, err := ParseLink(link, group)
	if err != nil {
		return nil, err
	}
	s.NOrigin = utils.Manual
	return s, nil
}

func countHash(n *Vmess, jsonStr string) string {
	hash := sha256.New()
	hash.Write([]byte{byte(n.NType)})
	hash.Write([]byte{byte(n.NOrigin)})
	hash.Write([]byte(n.NName))
	hash.Write([]byte(n.NGroup))
	if jsonStr == "" {
		data, _ := json.Marshal(n.JSON)
		jsonStr = string(data)
	}
	hash.Write([]byte(jsonStr))
	return hex.EncodeToString(hash.Sum(nil))
}

//ParseConn parse map to net.Conn
func ParseConn(n *utils.Point) (netUtils.Proxy, error) {
	x := new(Vmess)
	err := json.Unmarshal(n.Data, x)
	if err != nil {
		return nil, fmt.Errorf("parse vmess map failed: %v", err)
	}

	v, err := libVmess.NewVmess(
		x.Address,
		x.Port,
		x.UUID,
		"",
		x.Type,
		x.AlterID,
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

func unmarshalJSON(data []byte) (*JSON, error) {
	s := &struct {
		Address    string          `json:"add"`
		Port       json.RawMessage `json:"port"`
		UUID       string          `json:"id"`
		AlterID    json.RawMessage `json:"aid"`
		Ps         string          `json:"ps"`
		Net        string          `json:"net"`
		Type       string          `json:"type"`
		TLS        string          `json:"tls"`
		Host       string          `json:"host"`
		Path       string          `json:"path"`
		V          string          `json:"v"`
		VerifyCert bool            `json:"verify_cert"`
		Class      int             `json:"class"`
	}{}

	if err := json.Unmarshal(data, s); err != nil {
		return nil, fmt.Errorf("unmarshal failed: %v\nstr: %s\n", err, data)
	}

	return &JSON{
		Address:    s.Address,
		Port:       parseUint32(s.Port),
		UUID:       s.UUID,
		AlterID:    parseUint32(s.AlterID),
		Ps:         s.Ps,
		Net:        s.Net,
		Type:       s.Type,
		TLS:        s.TLS,
		Host:       s.Host,
		Path:       s.Path,
		V:          s.V,
		VerifyCert: s.VerifyCert,
		Class:      s.Class,
	}, nil
}

func parseUint32(s json.RawMessage) uint32 {
	var x uint32
	err := json.Unmarshal(s, &x)
	if err != nil {
		var y string
		err = json.Unmarshal(s, &y)
		if err != nil {
			log.Printf("unmarshal port failed: %v", err)
			return 0
		}
		z, err := strconv.ParseUint(y, 10, 32)
		if err != nil {
			log.Printf("parse port failed: %v", err)
			return 0
		}
		return uint32(z)
	}
	return x
}
