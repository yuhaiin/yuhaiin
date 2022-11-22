package node

import (
	"encoding/json"
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

	mg.DeleteNode("adada")

	data, _ := protojson.MarshalOptions{Indent: "  "}.Marshal(mg.Manager)
	data2, _ := json.MarshalIndent(mg.Manager, "", " ")
	t.Log(string(data), string(data2))
}
