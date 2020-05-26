package subscr

import (
	"testing"
)

func TestInitJSON(t *testing.T) {
	if err := InitJSON(); err != nil {
		t.Error(err)
	}
}

func TestAddLinkJSON(t *testing.T) {
	if err := AddLinkJSON("xxx"); err != nil {
		t.Error(err)
	}
}

func TestGetLinkFromInt(t *testing.T) {
	if err := GetLinkFromInt(); err != nil {
		t.Error(err)
	}
}

func TestChangeNowNode(t *testing.T) {
	pa, err := decodeJSON()
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
	if err := ChangeNowNode(group, node); err != nil {
		t.Error(err)
	}
}

func TestGetOneNode(t *testing.T) {
	pa, err := decodeJSON()
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
	x, err := GetOneNode(group, node)
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

func TestGetNowNodeGroupAndName(t *testing.T) {
	t.Log(GetNowNodeGroupAndName())
}

func TestGetGroup(t *testing.T) {
	t.Log(GetGroup())
}

func TestGetNode2(t *testing.T) {
	pa, err := decodeJSON()
	if err != nil {
		t.Error(err)
	}
	var group string
	for x := range pa.Node {
		group = x
		break
	}
	t.Log(GetNode(group))
}
