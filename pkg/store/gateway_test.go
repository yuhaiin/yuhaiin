package store

import (
	"bytes"
	"errors"
	"testing"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
)

func TestGatewaySQLiteRevisionAndTargetReferences(t *testing.T) {
	editor, _, _ := editorStore(t)
	ctx := t.Context()
	nodes := NewNodeStore(editor.db)
	if err := nodes.Save(ctx, contractnode.Node{ID: "node", Name: "Node", Enabled: true, Origin: "manual", Chain: []contractnode.Protocol{{Type: "direct", Direct: &contractnode.Direct{}}}}, 0); err != nil {
		t.Fatal(err)
	}
	selectors := NewSelectorStore(editor.db)
	selected, err := selectors.Save(ctx, contractnode.Selector{ID: "selector", Name: "Selector", NodeID: "node"})
	if err != nil {
		t.Fatal(err)
	}
	s := NewGatewayStore(editor.db)
	config := contract.Config{Gateways: []contract.Gateway{{ID: "g", Name: "Site", Default: contract.Action{Type: "forward", Outbound: contractroute.Target{Type: "selector", ID: selected.ID}}}}}
	saved, err := s.Save(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Revision != 1 {
		t.Fatal(saved.Revision)
	}
	if _, err := s.Save(ctx, config); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale config: %v", err)
	}
	if err := selectors.Delete(ctx, "selector"); err == nil {
		t.Fatal("deleted referenced selector")
	}
	loaded, err := NewGatewayStore(editor.db).Load(ctx)
	if err != nil || loaded.Gateways[0].Default.Outbound.ID != "selector" {
		t.Fatalf("reloaded=%+v err=%v", loaded, err)
	}
	loaded.Gateways[0].Default.Outbound = contractroute.Target{Type: "node", ID: "node"}
	saved, err = s.Save(ctx, loaded)
	if err != nil {
		t.Fatal(err)
	}
	if err := selectors.Delete(ctx, "selector"); err != nil {
		t.Fatal(err)
	}
	if err := nodes.Delete(ctx, "node"); err == nil {
		t.Fatal("deleted Gateway node target")
	}
	// Foreign-key failure rolls back both the reference deletion and config row.
	broken := saved
	broken.Gateways = append([]contract.Gateway(nil), saved.Gateways...)
	broken.Gateways[0].Default.Outbound.ID = "missing"
	if _, err := s.Save(ctx, broken); err == nil {
		t.Fatal("missing node reference accepted")
	}
	loaded, err = s.Load(ctx)
	if err != nil || loaded.Revision != saved.Revision || loaded.Gateways[0].Default.Outbound.ID != "node" {
		t.Fatalf("partial configuration save: %+v %v", loaded, err)
	}
}

func TestGatewayCAStoreCASAndConfigSeparation(t *testing.T) {
	editor, _, _ := editorStore(t)
	s := NewGatewayStore(editor.db)
	ctx := t.Context()
	revision, err := s.SaveCA(ctx, []byte("public-root"), []byte("private-key"), 0)
	if err != nil || revision != 1 {
		t.Fatalf("revision=%d err=%v", revision, err)
	}
	if _, err := s.SaveCA(ctx, []byte("other"), []byte("other-key"), 0); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale CA save: %v", err)
	}
	root, key, revision, err := NewGatewayStore(editor.db).LoadCA(ctx)
	if err != nil || revision != 1 || !bytes.Equal(root, []byte("public-root")) || !bytes.Equal(key, []byte("private-key")) {
		t.Fatal("CA material changed on reload")
	}
	var count int
	if err := editor.db.QueryRowContext(ctx, `SELECT count(*) FROM gateway_configuration WHERE data_json LIKE '%private-key%'`).Scan(&count); err != nil || count != 0 {
		t.Fatal("CA key entered normal configuration")
	}
}
