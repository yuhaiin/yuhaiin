package subscr

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestAddNode(t *testing.T) {
	mg := &manager{
		Manager: &node.Manager{},
	}

	mg.AddNode(&node.Point{
		Hash:  "adadav",
		Name:  "feefe",
		Group: "group",
	})
	mg.AddNode(&node.Point{
		Hash:  "adadab",
		Name:  "fafaf",
		Group: "group",
	})
	mg.AddNode(&node.Point{
		Hash:  "adada",
		Name:  "fazczfzf",
		Group: "group",
	})

	t.Log(mg.Manager)

	mg.DeleteNode("adada")

	data, _ := protojson.MarshalOptions{Indent: "  "}.Marshal(mg.Manager)
	t.Log(string(data))
}
