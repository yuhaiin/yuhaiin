package node

import (
	"errors"
	"uuid"

	"github.com/Asutorufa/yuhaiin/pkg/contract/node"
)

// PrepareImportCommit reuses the import parser and intra-batch reference
// rewriting. Only public IDs and save outcomes are returned by the HTTP commit.
func PrepareImportCommit(request node.ImportCommit) ([]node.Node, []int, error) {
	if len(request.IDs) > 1000 || len(request.Indices) > 1000 {
		return nil, nil, errors.New("at most 1000 nodes may be committed at once")
	}
	preview, err := PreviewImport(node.ImportRequest{Text: request.Text, Group: request.Group})
	if err != nil {
		return nil, nil, err
	}
	if len(request.IDs) != len(preview.Items) {
		return nil, nil, errors.New("import source and preview IDs do not match")
	}
	seen := map[string]bool{}
	mapping := map[string]string{}
	for i, id := range request.IDs {
		if _, err := uuid.Parse(id); err != nil || seen[id] {
			return nil, nil, errors.New("import IDs must be distinct UUIDs")
		}
		seen[id] = true
		mapping[preview.Items[i].ID] = id
		preview.Items[i].ID = id
	}
	for i := range preview.Items {
		for j := range preview.Items[i].Chain {
			remapImportProtocol(&preview.Items[i].Chain[j], mapping)
		}
	}
	indices := request.Indices
	if indices == nil {
		indices = make([]int, len(preview.Items))
		for i := range indices {
			indices[i] = i
		}
	}
	selected := map[int]bool{}
	for _, i := range indices {
		if i < 0 || i >= len(preview.Items) || selected[i] {
			return nil, nil, errors.New("import indices must be distinct preview positions")
		}
		selected[i] = true
	}
	return preview.Items, indices, nil
}
