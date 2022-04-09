package subscr

import (
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
)

func TestAddNode(t *testing.T) {
	mg := &manager{
		Manager: &Manager{},
	}

	mg.AddNode(&Point{
		Hash:  "adadav",
		Name:  "feefe",
		Group: "group",
	})
	mg.AddNode(&Point{
		Hash:  "adadab",
		Name:  "fafaf",
		Group: "group",
	})
	mg.AddNode(&Point{
		Hash:  "adada",
		Name:  "fazczfzf",
		Group: "group",
	})

	t.Log(mg.Manager)

	mg.DeleteNode("adada")

	data, _ := protojson.MarshalOptions{Indent: "  "}.Marshal(mg.Manager)
	t.Log(string(data))
}
