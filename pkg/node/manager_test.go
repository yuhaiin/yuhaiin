package node

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestAddNode(t *testing.T) {
	mg := &manager{
		Manager: &node.Manager{},
	}

	mg.AddNode(&point.Point{
		Hash:  "adadav",
		Name:  "feefe",
		Group: "group",
	})
	mg.AddNode(&point.Point{
		Hash:  "adadab",
		Name:  "fafaf",
		Group: "group",
	})
	mg.AddNode(&point.Point{
		Hash:  "adada",
		Name:  "fazczfzf",
		Group: "group",
	})

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
