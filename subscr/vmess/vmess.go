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
	Host       string `json:"host"` // tls or websocket host
	Path       string `json:"path"` // tls or websocket path
	TLS        string `json:"tls"`
	VerifyCert bool   `json:"verify_cert"`
	Address    string `json:"add"` // address
	Port       uint32 `json:"port"`
	AlterID    uint32 `json:"aid"`  // alter id
	Net        string `json:"net"`  // tls or ws
	Type       string `json:"type"` // security type
	V          string `json:"v"`
	Ps         string `json:"ps"` // name
	UUID       string `json:"id"` // uuid
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

	for key := range n {
		switch key {
		case "add":
			node.Address = common.Interface2string(n[key])
		case "port":
			node.Port = uint32(common.Interface2Float64(n[key]))
		case "type":
			node.Type = common.Interface2string(n[key])
		case "id":
			node.UUID = common.Interface2string(n[key])
		case "aid":
			node.AlterID = uint32(common.Interface2Float64(n[key]))
		case "v":
			node.V = common.Interface2string(n[key])
		case "net":
			node.Net = common.Interface2string(n[key])
		case "host":
			node.Host = common.Interface2string(n[key])
		case "path":
			node.Path = common.Interface2string(n[key])
		case "tls":
			node.TLS = common.Interface2string(n[key])
		case "verify_cert":
			node.VerifyCert = common.Interface2Bool(n[key])
		case "ps":
			node.Ps = common.Interface2string(n[key])
		case "class":
			node.Class = int(common.Interface2Float64(n[key]))
		case "name":
			node.NName = common.Interface2string(n[key])
		case "group":
			node.NGroup = common.Interface2string(n[key])
		case "hash":
			node.NHash = common.Interface2string(n[key])
		}
	}
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
		x.TLS,
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
