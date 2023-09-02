package node

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/subscribe"
	pt "github.com/Asutorufa/yuhaiin/pkg/protos/node/tag"
	"github.com/Asutorufa/yuhaiin/pkg/utils/jsondb"
)

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
