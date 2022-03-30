package subscr

import (
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
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
	t.Log((&vmess{}).ParseLink([]byte(data)))
}

func TestUnmarshal2(t *testing.T) {
	str := `{"host":"www.example.com","path":"/test","tls":"","verify_cert":true,"add":"example.com","port":"443","aid":"1","net":"ws","type":"none","v":"2","ps":"example","id":"2f3b2bb9-b2ae-3919-95d4-702ce7c02262","class":0}`
	x := &Vmess{}
	err := protojson.Unmarshal([]byte(str), x)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	t.Log(x)
	str = `{"host":"www.example.com","path":"/test","tls":"","verify_cert":true,"add":"example.com","port":443,"aid":"1","net":"ws","type":"none","v":"2","ps":"example","id":"2f3b2bb9-b2ae-3919-95d4-702ce7c02262","class":0}`
	z := &Vmess2{}
	err = protojson.UnmarshalOptions{}.Unmarshal([]byte(str), z)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	t.Log(z)
}

// func TestVmess(t *testing.T) {
// 	z, err := createConn()
// 	require.NoError(t, err)

// 	tt := &http.Client{
// 		Transport: &http.Transport{
// 			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
// 				return z.Conn(addr)
// 			},
// 		},
// 	}

// 	req := http.Request{
// 		Method: "GET",
// 		URL: &url.URL{
// 			Scheme: "http",
// 			Host:   "ip.sb",
// 		},
// 		Header: make(http.Header),
// 	}
// 	req.Header.Set("User-Agent", "curl/v2.4.1")
// 	resp, err := tt.Do(&req)
// 	t.Error(err)
// 	require.Nil(t, err)
// 	defer resp.Body.Close()
// 	data, err := ioutil.ReadAll(resp.Body)
// 	require.Nil(t, err)
// 	t.Log(string(data))
// }
