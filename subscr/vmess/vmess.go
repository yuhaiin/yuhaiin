package vmess

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"

	libVmess "github.com/Asutorufa/yuhaiin/net/proxy/vmess"
	"github.com/Asutorufa/yuhaiin/subscr/common"
)

//{
//"host":"",
//"path":"",
//"tls":"",
//"verify_cert":true,
//"add":"127.0.0.1",
//"port":0,
//"aid":2,
//"net":"tcp",
//"type":"none",
//"v":"2",
//"ps":"name",
//"id":"cccc-cccc-dddd-aaa-46a1aaaaaa",
//"class":1
//}

//Vmess vmess
type Vmess struct {
	common.NodeMessage
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
// test vmess://eyJob3N0IjoiIiwicGF0aCI6IiIsInRscyI6IiIsInZlcmlmeV9jZXJ0Ijp0cnVlLCJhZGQiOiIxMjcuMC4wLjEiLCJwb3J0IjowLCJhaWQiOjIsIm5ldCI6InRjcCIsInR5cGUiOiJub25lIiwidiI6IjIiLCJwcyI6Im5hbWUiLCJpZCI6ImNjY2MtY2NjYy1kZGRkLWFhYS00NmExYWFhYWFhIiwiY2xhc3MiOjF9Cg
func ParseLink(str []byte, group string) (*Vmess, error) {
	s := string(str)
	s = strings.ReplaceAll(s, "vmess://", "")
	data := common.Base64DStr(s)

	vmess := &JSON{}
	if err := json.Unmarshal([]byte(data), vmess); err != nil {
		return nil, fmt.Errorf("unmarshal failed: %v\nstr: %s\nRaw: %s", err, data, str)
	}

	n := &Vmess{
		NodeMessage: common.NodeMessage{
			NName:   "[vmess]" + vmess.Ps,
			NGroup:  group,
			NType:   common.Vmess,
			NOrigin: common.Remote,
		},
		JSON: *vmess,
	}
	n.NHash = countHash(n, string(data))

	return n, nil
}

// ParseLinkManual parse a manual base64 encode vmess link
func ParseLinkManual(link []byte, group string) (*Vmess, error) {
	s, err := ParseLink(link, group)
	if err != nil {
		return nil, err
	}
	s.NOrigin = common.Manual
	return s, nil
}

// ParseMap parse vmess map read from config json
func ParseMap(n map[string]interface{}) (*Vmess, error) {
	if n == nil {
		return nil, errors.New("map is nil")
	}

	node := new(Vmess)
	node.NType = common.Shadowsocksr
	node.Address = common.I2string(n["add"])
	node.Port = uint32(common.I2Float64(n["port"]))
	node.Type = common.I2string(n["type"])
	node.UUID = common.I2string(n["id"])
	node.AlterID = uint32(common.I2Float64(n["aid"]))
	node.V = common.I2string(n["v"])
	node.Net = common.I2string(n["net"])
	node.Host = common.I2string(n["host"])
	node.Path = common.I2string(n["path"])
	node.TLS = common.I2string(n["tls"])
	node.VerifyCert = common.I2Bool(n["verify_cert"])
	node.Ps = common.I2string(n["ps"])
	node.Class = int(common.I2Float64(n["class"]))
	node.NName = common.I2string(n["name"])
	node.NGroup = common.I2string(n["group"])
	node.NHash = common.I2string(n["hash"])
	if node.NHash == "" {
		node.NHash = countHash(node, "")
	}
	return node, nil
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
func ParseConn(n map[string]interface{}) (func(string) (net.Conn, error), error) {
	x, err := ParseMap(n)
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

	return v.Conn, nil
}
