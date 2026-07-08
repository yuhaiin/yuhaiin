package node

import (
	"encoding/json/v2"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/schema/node"
	"github.com/Asutorufa/yuhaiin/pkg/schema/tools"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	mg := NewManager(tools.PathGenerator.State(t.TempDir()))
	t.Cleanup(func() { _ = mg.Close() })
	return mg
}

func TestAddNode(t *testing.T) {
	mg := newTestManager(t)

	p1 := node.Point_builder{
		Name:  new("feefe"),
		Group: new("group"),
	}.Build()
	p2 := node.Point_builder{
		Name:  new("fafaf"),
		Group: new("group"),
	}.Build()
	p3 := node.Point_builder{
		Name:  new("fazczfzf"),
		Group: new("group"),
	}.Build()
	p4 := node.Point_builder{
		Name:  new("fazczfzf"),
		Group: new("group"),
	}.Build()
	if err := mg.SaveNode(p1, p2, p3, p4); err != nil {
		t.Fatal(err)
	}

	if err := mg.AddTag("test_tag", 1, p2.GetHash()); err != nil {
		t.Fatal(err)
	}
	if err := mg.AddTag("test_tag3", 0, p3.GetHash()); err != nil {
		t.Fatal(err)
	}
	if err := mg.AddTag("test_tag2", 0, p2.GetHash()); err != nil {
		t.Fatal(err)
	}
	if err := mg.AddTag("test_tag2", 0, p3.GetHash()); err != nil {
		t.Fatal(err)
	}
	if err := mg.DeleteTag("test_tag2"); err != nil {
		t.Fatal(err)
	}
	if err := mg.DeleteNode(p3.GetHash()); err != nil {
		t.Fatal(err)
	}

	loaded, err := mg.persist.Load()
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(loaded)
	t.Log(string(data))
}
