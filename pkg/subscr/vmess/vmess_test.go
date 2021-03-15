package vmess

import (
	"encoding/json"
	"strings"
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

func TestUnmarshal(t *testing.T) {
	str := `{"host":"www.example.com","path":"/test","tls":"","verify_cert":true,"add":"example.com","port":"443","aid":"1","net":"ws","type":"none","v":"2","ps":"example","id":"2f3b2bb9-b2ae-3919-95d4-702ce7c02262","class":0}`

	type JSON2 struct {
		Address string          `json:"add"` // address
		Port    json.RawMessage `json:"port"`
		UUID    string          `json:"id"`   // uuid
		AlterID json.RawMessage `json:"aid"`  // alter id
		Ps      string          `json:"ps"`   // name
		Net     string          `json:"net"`  // (tcp\kcp\ws\h2\quic)
		Type    string          `json:"type"` // fake type [(none\http\srtp\utp\wechat-video) *tcp or kcp or QUIC]
		TLS     string          `json:"tls"`

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

	a := &JSON2{}
	err := json.Unmarshal([]byte(str), a)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Log(a, strings.ReplaceAll(string(a.Port), "\"", ""))

	str = `{"host":"www.example.com","path":"/test","tls":"","verify_cert":true,"add":"example.com","port":443,"aid":"1","net":"ws","type":"none","v":"2","ps":"example","id":"2f3b2bb9-b2ae-3919-95d4-702ce7c02262","class":0}`
	err = json.Unmarshal([]byte(str), a)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Log(a, string(a.Port))
}
