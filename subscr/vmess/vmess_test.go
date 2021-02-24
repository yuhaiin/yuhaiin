package vmess

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestGetVmess(t *testing.T) {
	// str := "vmess://eyJob3N0IjoiIiwicGF0aCI6IiIsInRscyI6IiIsInZlcmlmeV9jZXJ0Ijp0cnVlLCJhZGQiOiIxMjcuMC4wLjEiLCJwb3J0IjowLCJhaWQiOjIsIm5ldCI6InRjcCIsInR5cGUiOiJub25lIiwidiI6IjIiLCJwcyI6Im5hbWUiLCJpZCI6ImNjY2MtY2NjYy1kZGRkLWFhYS00NmExYWFhYWFhIiwiY2xhc3MiOjF9Cg"
	x := &VmessJson{
		Host:       "example.com",
		Path:       "/",
		TLS:        "",
		VerifyCert: false,
		Address:    "example.com",
		Port:       1080,
		AlterID:    2,
		Net:        "tcp",
		Type:       "none",
		V:          "2",
		Ps:         "name",
		UUID:       "xxxx-xxxx-xxxx-xxxxxxxx-xxxxx",
		Class:      2,
	}

	s, err := json.Marshal(x)
	if err != nil {
		t.Error(err)
	}

	data := "vmess://" + base64.RawStdEncoding.EncodeToString(s)

	t.Log(data)

	t.Log(ParseLink([]byte(data), ""))
}
