package node

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/utils/jsondb"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func TestAddNode(t *testing.T) {
	mg := &Manager{
		store: store,
		db: &DB{db: &jsondb.DB[*node.Node]{
			Data: node.Node_builder{Manager: &node.Manager{}}.Build(),
		}},
	}

	p1 := point.Point_builder{
		Name:  proto.String("feefe"),
		Group: proto.String("group"),
	}.Build()
	p2 := point.Point_builder{
		Name:  proto.String("fafaf"),
		Group: proto.String("group"),
	}.Build()
	p3 := point.Point_builder{
		Name:  proto.String("fazczfzf"),
		Group: proto.String("group"),
	}.Build()
	p4 := point.Point_builder{
		Name:  proto.String("fazczfzf"),
		Group: proto.String("group"),
	}.Build()
	mg.SaveNode(p1, p2, p3, p4)

	t.Log(mg.db.db.Data)

	mg.AddTag("test_tag", 1, p2.GetHash())
	mg.AddTag("test_tag3", 0, p3.GetHash())
	mg.AddTag("test_tag2", 0, p2.GetHash())
	mg.AddTag("test_tag2", 0, p3.GetHash())
	mg.DeleteTag("test_tag2")
	mg.DeleteNode(p3.GetHash())

	data, _ := protojson.MarshalOptions{Indent: "  "}.Marshal(mg.db.db.Data)
	t.Log(string(data))
}
