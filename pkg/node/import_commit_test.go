package node_test

import (
	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/node"
	"slices"
	"testing"
	"uuid"
)

func TestImportCommitRetainsPreviewIDsAndRetrySelection(t *testing.T) {
	source := `[{"id":"old","name":"Server","chain":[{"type":"direct","direct":{}}]},{"name":"Group","chain":[{"type":"set","set":{"nodes":["old"]}}]}]`
	ids := []string{uuid.New().String(), uuid.New().String()}
	request := contractnode.ImportCommit{Text: source, IDs: ids}
	items, selected, err := node.PrepareImportCommit(request)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(selected, []int{0, 1}) || items[0].ID != ids[0] || items[1].ID != ids[1] || items[1].Chain[0].Set.Nodes[0] != ids[0] {
		t.Fatal("preview IDs/references were not retained")
	}
	request.Indices = []int{1}
	retry, selected, err := node.PrepareImportCommit(request)
	if err != nil || !slices.Equal(selected, []int{1}) || retry[0].ID != items[0].ID || retry[1].Chain[0].Set.Nodes[0] != ids[0] {
		t.Fatal("retry changed IDs or selection", err)
	}
	request.Indices = []int{}
	_, selected, err = node.PrepareImportCommit(request)
	if err != nil || len(selected) != 0 {
		t.Fatal("explicit empty selection saved nodes", err)
	}
	for _, invalid := range []contractnode.ImportCommit{
		{Text: source, IDs: ids[:1]}, {Text: source, IDs: []string{ids[0], ids[0]}},
		{Text: source, IDs: []string{"invalid", ids[1]}}, {Text: source, IDs: ids, Indices: []int{1, 1}},
		{Text: source, IDs: ids, Indices: []int{-1}}, {Text: source, IDs: ids, Indices: []int{2}},
	} {
		if _, _, err := node.PrepareImportCommit(invalid); err == nil {
			t.Fatal("accepted invalid import selection")
		}
	}
}
