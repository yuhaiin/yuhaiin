package subscr

import (
	"testing"
)

func TestGetLinkFromInt(t *testing.T) {
	if err := GetLinkFromInt(); err != nil {
		t.Error(err)
	}
}

func TestGetNowNode(t *testing.T) {
	pa, err := GetNowNode()
	if err != nil {
		t.Log(err)
	}
	switch pa.(type) {
	case *Shadowsocks:
		t.Log(pa.(*Shadowsocks))
	case *Shadowsocksr:
		t.Log(pa.(*Shadowsocksr))
	}
}

func mapc(a map[string]string) {
	a["a"] = "a"
}

func TestMap(t *testing.T) {
	b := map[string]string{}
	mapc(b)
	t.Log(b["a"])
}
