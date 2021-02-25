package vmess

import (
	"testing"
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

func TestGetVmess(t *testing.T) {
	data := "vmess://eyJob3N0IjoiIiwicGF0aCI6IiIsInRscyI6IiIsInZlc" +
		"mlmeV9jZXJ0Ijp0cnVlLCJhZGQiOiIxMjcuMC4wLjEiLCJwb3J" +
		"0IjowLCJhaWQiOjIsIm5ldCI6InRjcCIsInR5cGUiOiJub25lI" +
		"iwidiI6IjIiLCJwcyI6Im5hbWUiLCJpZCI6ImNjY2MtY2NjYy1" +
		"kZGRkLWFhYS00NmExYWFhYWFhIiwiY2xhc3MiOjF9Cg"
	t.Log(ParseLink([]byte(data), ""))
}
