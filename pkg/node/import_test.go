package node_test

import (
	"encoding/base64"
	"strings"
	"testing"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/node"
)

func TestPreviewImportCopiesAndRebindsNodes(t *testing.T) {
	preview, err := node.PreviewImport(contractnode.ImportRequest{Group: "imported", Text: `[
		{"id":"old","name":"Server","origin":"remote","chain":[{"type":"direct","direct":{}}]},
		{"id":"group","name":"Failover","enabled":false,"chain":[{"type":"network_split","network_split":{"tcp":{"type":"set","set":{"nodes":["old"]}}}}]},
		{"name":"Endpoint","chain":[{"type":"point_as_endpoint","point_as_endpoint":{"hash":"old"}}]}
	]`})
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.Items) != 3 || len(preview.Errors) != 0 {
		t.Fatalf("preview: %+v", preview)
	}
	first := preview.Items[0]
	if first.ID == "old" || !first.Enabled || first.Origin != "manual" || first.Group != "imported" {
		t.Fatalf("first node: %+v", first)
	}
	if preview.Items[1].Enabled || preview.Items[1].Chain[0].NetworkSplit.TCP.Set.Nodes[0] != first.ID || preview.Items[2].Chain[0].PointAsEndpoint.Hash != first.ID {
		t.Fatalf("references not rebound: %+v", preview.Items)
	}
}

func TestPreviewImportReportsInvalidItemsAndDuplicates(t *testing.T) {
	preview, err := node.PreviewImport(contractnode.ImportRequest{Text: `{"items":[
		{"id":"same","name":"one","chain":[{"type":"direct","direct":{}}]},
		{"id":"same","name":"two","chain":[{"type":"direct","direct":{}}]},
		{"name":"invalid","chain":[{"type":"direct","reject":{}}]}
	]}`})
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.Items) != 1 || len(preview.Errors) != 2 || preview.Errors[0].Line != 2 || preview.Errors[1].Line != 3 {
		t.Fatalf("preview: %+v", preview)
	}
	for _, text := range []string{"", "[]", "{", strings.Repeat("x", (4<<20)+1)} {
		if _, err := node.PreviewImport(contractnode.ImportRequest{Text: text}); err == nil {
			t.Fatalf("accepted invalid import %q", text[:min(len(text), 20)])
		}
	}
}

func TestPreviewImportShareLinksAndEncodedSubscription(t *testing.T) {
	link := "trojan://secret@server.example:443#My%20server"
	for _, text := range []string{link, base64.StdEncoding.EncodeToString([]byte(link))} {
		preview, err := node.PreviewImport(contractnode.ImportRequest{Text: text})
		if err != nil {
			t.Fatal(err)
		}
		if len(preview.Items) != 1 || len(preview.Errors) != 0 || !strings.Contains(preview.Items[0].Name, "My server") {
			t.Fatalf("preview: %+v", preview)
		}
	}
	preview, err := node.PreviewImport(contractnode.ImportRequest{Text: link + "\nunknown://secret@host"})
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.Items) != 1 || len(preview.Errors) != 1 || strings.Contains(preview.Errors[0].Message, "secret") {
		t.Fatalf("preview: %+v", preview)
	}
}
