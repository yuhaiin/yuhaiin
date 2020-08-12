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

func TestAllOption(t *testing.T) {
	nodes := Node{
		Node: map[string]map[string]interface{}{},
	}
	addOneNode(map[string]interface{}{"n_origin": remote}, "testGroup", "testName", nodes.Node)
	addOneNode(map[string]interface{}{"n_origin": manual}, "testGroup", "testName2", nodes.Node)
	addOneNode(map[string]interface{}{"n_origin": remote}, "testGroup2", "testName", nodes.Node)
	printNodes(nodes.Node)

	//t.Log("Delete Test")
	//deleteOneNode("testGroup2", "testName", nodes.Node)
	//printNodes(nodes.Node)

	t.Log("Delete Remote Test")
	deleteRemoteNodes(nodes.Node)
	printNodes(nodes.Node)
}
