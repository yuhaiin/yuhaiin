package subscr

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/subscr/common"

	shadowsocksr2 "github.com/Asutorufa/yuhaiin/subscr/shadowsocksr"

	shadowsocks2 "github.com/Asutorufa/yuhaiin/subscr/shadowsocks"
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
	case *shadowsocks2.Shadowsocks:
		t.Log(pa.(*shadowsocks2.Shadowsocks))
	case *shadowsocksr2.Shadowsocksr:
		t.Log(pa.(*shadowsocksr2.Shadowsocksr))
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
	addOneNode(map[string]interface{}{"n_origin": common.Remote}, "testGroup", "testName", nodes.Node)
	addOneNode(map[string]interface{}{"n_origin": common.Manual}, "testGroup", "testName2", nodes.Node)
	addOneNode(map[string]interface{}{"n_origin": common.Remote}, "testGroup2", "testName", nodes.Node)
	s := &shadowsocks2.Shadowsocks{}
	s.NOrigin = common.Manual
	s.NName = "name"
	addOneNode(&shadowsocks2.Shadowsocks{}, "testGroup3", "testName", nodes.Node)
	printNodes(nodes.Node)

	//t.Log("Delete Test")
	//deleteOneNode("testGroup2", "testName", nodes.Node)
	//printNodes(nodes.Node)

	t.Log("Delete Remote Test")
	deleteAllRemoteNodes(nodes.Node)
	printNodes(nodes.Node)
}

func TestDecode(t *testing.T) {
	t.Log(decodeJSON())
}
