package subscr

import (
	"testing"
)

func TestInitJSON2(t *testing.T) {
	if err := InitJSON2(); err != nil {
		t.Error(err)
	}
}

func TestAddLinkJSON2(t *testing.T) {
	if err := AddLinkJSON2("xxx"); err != nil {
		t.Error(err)
	}
}

func TestGetLinkFromInt2(t *testing.T) {
	if err := GetLinkFromInt2(); err != nil {
		t.Error(err)
	}
}

func TestChangeNowNode2(t *testing.T) {
	pa, err := decodeJSON2()
	if err != nil {
		t.Error(err)
	}
	var group, node string
	for x := range pa.Node {
		group = x
		break
	}
	for x := range pa.Node[group] {
		node = x
		break
	}
	if err := ChangeNowNode2(group, node); err != nil {
		t.Error(err)
	}
}

func TestGetOneNode2(t *testing.T) {
	pa, err := decodeJSON2()
	if err != nil {
		t.Error(err)
	}
	var group, node string
	for x := range pa.Node {
		group = x
		break
	}
	for x := range pa.Node[group] {
		node = x
		break
	}
	x, err := GetOneNode2(group, node)
	if err != nil {
		t.Error(err)
	}
	switch x.(type) {
	case *Shadowsocks:
		t.Log(x.(*Shadowsocks))
	case *Shadowsocksr:
		t.Log(x.(*Shadowsocksr))
	}
}
func TestGetNowNode(t *testing.T) {
	pa, err := GetNowNode2()
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

func TestGetGroup2(t *testing.T) {
	t.Log(GetGroup2())
}

func TestGetNode2(t *testing.T) {
	pa, err := decodeJSON2()
	if err != nil {
		t.Error(err)
	}
	var group string
	for x := range pa.Node {
		group = x
		break
	}
	t.Log(GetNode2(group))
}
