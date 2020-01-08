package subscription

import (
	"SsrMicroClient/base64d"
	"encoding/json"
	"fmt"
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
type Vmess struct {
	Host       string `json:"host"`
	Path       string `json:"path"`
	Tls        string `json:"tls"`
	VerifyCert bool   `json:"verify_cert"`
	Add        string `json:"add"`
	Port       int    `json:"port"`
	Aid        int    `json:"aid"`
	Net        string `json:"net"`
	Type       string `json:"type"`
	V          string `json:"v"`
	Ps         string `json:"ps"`
	Id         string `json:"id"`
	Class      int    `json:"class"`
}

// test vmess://eyJob3N0IjoiIiwicGF0aCI6IiIsInRscyI6IiIsInZlcmlmeV9jZXJ0Ijp0cnVlLCJhZGQiOiIxMjcuMC4wLjEiLCJwb3J0IjowLCJhaWQiOjIsIm5ldCI6InRjcCIsInR5cGUiOiJub25lIiwidiI6IjIiLCJwcyI6Im5hbWUiLCJpZCI6ImNjY2MtY2NjYy1kZGRkLWFhYS00NmExYWFhYWFhIiwiY2xhc3MiOjF9Cg
func GetVmess(str string) {
	jsonStr := base64d.Base64d(str)
	fmt.Println(jsonStr)
	vmess := &Vmess{}
	if err := json.Unmarshal([]byte(jsonStr), vmess); err != nil {
		fmt.Println(err)
	}
	fmt.Println(vmess)
}
