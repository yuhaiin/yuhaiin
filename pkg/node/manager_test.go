package node

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func TestAddNode(t *testing.T) {
	mg := &manager{
		Manager: &node.Manager{},
	}

	mg.AddNode(point.Point_builder{
		Hash:  proto.String("adadav"),
		Name:  proto.String("feefe"),
		Group: proto.String("group"),
	}.Build())
	mg.AddNode(point.Point_builder{
		Hash:  proto.String("adadab"),
		Name:  proto.String("fafaf"),
		Group: proto.String("group"),
	}.Build())
	mg.AddNode(point.Point_builder{
		Hash:  proto.String("adada"),
		Name:  proto.String("fazczfzf"),
		Group: proto.String("group"),
	}.Build())

	t.Log(mg.Manager)

	mg.AddTag("test_tag", 1, "adadab")
	mg.AddTag("test_tag3", 0, "adada")
	mg.AddTag("test_tag2", 0, "adadab")
	mg.AddTag("test_tag2", 0, "adada")
	mg.DeleteTag("test_tag2")
	mg.DeleteNode("adada")

	data, _ := protojson.MarshalOptions{Indent: "  "}.Marshal(mg.Manager)
	t.Log(string(data))
}
