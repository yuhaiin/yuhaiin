package node

import (
	"testing"

	"slices"

	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"github.com/Asutorufa/yuhaiin/pkg/utils/jsondb"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestDelete(t *testing.T) {
	a := []string{"a", "b", "c"}

	for i := range a {
		if a[i] != "b" {
			continue
		}

		t.Log(i, a[:i], a[i:])
		a = slices.Delete(a, i, i+1)
		break
	}

	t.Log(a)
}

func TestMergeDefault(t *testing.T) {
	defaultNode := (&node.Node_builder{
		Tcp:   &node.Point{},
		Udp:   &node.Point{},
		Links: map[string]*node.Link{},
		Manager: (&node.Manager_builder{
			Nodes: map[string]*node.Point{},
			Tags:  map[string]*node.Tags{},
		}).Build(),
	}).Build()

	src := &node.Node{}

	jsondb.MergeDefault(src.ProtoReflect(), defaultNode.ProtoReflect())

	t.Log(src.GetLinks() == nil)

	data, err := protojson.MarshalOptions{
		Multiline:         true,
		EmitDefaultValues: true,
	}.Marshal(defaultNode)
	assert.NoError(t, err)

	t.Log(string(data))
}
