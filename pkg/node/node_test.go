package node

import (
	"reflect"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/subscribe"
	pt "github.com/Asutorufa/yuhaiin/pkg/protos/node/tag"
	"github.com/Asutorufa/yuhaiin/pkg/utils/jsondb"
)

func TestDelete(t *testing.T) {
	a := []string{"a", "b", "c"}

	for i := range a {
		if a[i] != "b" {
			continue
		}

		t.Log(i, a[:i], a[i:])
		a = append(a[:i], a[i+1:]...)
		break
	}

	t.Log(a)
}

func TestProtoMsgType(t *testing.T) {
	p := &protocol.Protocol{
		Protocol: &protocol.Protocol_None{},
	}

	t.Log(reflect.TypeOf(p.GetProtocol()) == reflect.TypeOf(&protocol.Protocol_None{}))
}

func TestMergeDefault(t *testing.T) {
	defaultNode := &node.Node{
		Tcp:   &point.Point{},
		Udp:   &point.Point{},
		Links: map[string]*subscribe.Link{},
		Manager: &node.Manager{
			GroupsV2: map[string]*node.Nodes{},
			Nodes:    map[string]*point.Point{},
			Tags:     map[string]*pt.Tags{},
		},
	}

	src := &node.Node{}

	jsondb.MergeDefault(src.ProtoReflect(), defaultNode.ProtoReflect())

	t.Log(src.Links == nil, src.Manager.GroupsV2 == nil)
}
