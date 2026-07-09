package store

import (
	"context"
	"encoding/json/v2"
	"os"
	"testing"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	pn "github.com/Asutorufa/yuhaiin/pkg/legacy/schema/node"
	"github.com/Asutorufa/yuhaiin/pkg/paths"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func TestSqliteNodeStoreImportsAndPersists(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	legacy := defaultNodeData()
	point := pn.Point_builder{
		Hash:   new("hash-1"),
		Name:   new("alpha-node"),
		Group:  new("remote-group"),
		Origin: pn.Origin_remote.Enum(),
	}.Build()
	legacy.GetManager().GetNodes()[point.GetHash()] = point
	legacy.SetTcp(point)
	legacy.SetUdp(point)
	legacy.GetManager().GetTags()["fast"] = pn.Tags_builder{
		Tag:  new("fast"),
		Type: pn.TagType_node.Enum(),
		Hash: []string{point.GetHash()},
	}.Build()
	legacy.GetLinks()["remote-group"] = pn.Link_builder{
		Name: new("remote-group"),
		Url:  new("https://example.com/sub.txt"),
	}.Build()
	legacy.GetManager().GetPublishes()["pub"] = pn.Publish_builder{
		Name:     new("pub"),
		Path:     new("/pub"),
		Password: new("secret"),
		Points:   []string{point.GetHash()},
	}.Build()

	data, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal legacy node failed: %v", err)
	}
	if err := os.WriteFile(paths.PathGenerator.Node(dir), data, 0o600); err != nil {
		t.Fatalf("write legacy node failed: %v", err)
	}

	store := NewSqliteNodeStore(paths.PathGenerator.State(dir))
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("load sqlite node store failed: %v", err)
	}
	if got := loaded.GetTcp().GetHash(); got != point.GetHash() {
		t.Fatalf("expected selected tcp %q, got %q", point.GetHash(), got)
	}
	if _, ok := loaded.GetManager().GetTags()["fast"]; !ok {
		t.Fatalf("expected imported tag")
	}
	if _, ok := loaded.GetLinks()["remote-group"]; !ok {
		t.Fatalf("expected imported subscription link")
	}
	if _, ok := loaded.GetManager().GetPublishes()["pub"]; !ok {
		t.Fatalf("expected imported publish")
	}

	loaded.GetManager().GetNodes()[point.GetHash()].SetName("alpha-node-renamed")
	if err := store.Save(loaded); err != nil {
		t.Fatalf("save sqlite node store failed: %v", err)
	}

	reloaded, err := store.Load()
	if err != nil {
		t.Fatalf("reload sqlite node store failed: %v", err)
	}
	if got := reloaded.GetManager().GetNodes()[point.GetHash()].GetName(); got != "alpha-node-renamed" {
		t.Fatalf("expected renamed node, got %q", got)
	}

	sqliteStore, err := storagesqlite.Open(context.Background(), paths.PathGenerator.State(dir))
	if err != nil {
		t.Fatalf("open sqlite for fts check failed: %v", err)
	}
	defer sqliteStore.Close()

	var hits int
	if err := sqliteStore.DB().QueryRowContext(context.Background(), `
		SELECT COUNT(*)
		FROM nodes_fts
		WHERE nodes_fts MATCH 'alpha'
	`).Scan(&hits); err != nil {
		t.Fatalf("query nodes fts failed: %v", err)
	}
	if hits == 0 {
		t.Fatalf("expected nodes_fts hit for alpha")
	}

	manual := pn.Point_builder{
		Hash:   new("manual-1"),
		Name:   new("manual-node"),
		Group:  new("remote-group"),
		Origin: pn.Origin_manual.Enum(),
	}.Build()
	oldRemote := pn.Point_builder{
		Hash:   new("old-remote"),
		Name:   new("old-remote-node"),
		Group:  new("remote-group"),
		Origin: pn.Origin_remote.Enum(),
	}.Build()
	if err := store.SaveNodes(manual, oldRemote); err != nil {
		t.Fatalf("seed nodes before replace failed: %v", err)
	}

	newRemote := pn.Point_builder{
		Hash: new("new-remote"),
		Name: new("new-remote-node"),
	}.Build()
	if err := store.ReplaceRemoteNodes("remote-group", newRemote); err != nil {
		t.Fatalf("replace remote nodes failed: %v", err)
	}

	if _, ok, err := store.GetNode(manual.GetHash()); err != nil || !ok {
		t.Fatalf("expected manual node to survive remote replace, ok=%v err=%v", ok, err)
	}
	if _, ok, err := store.GetNode(oldRemote.GetHash()); err != nil || ok {
		t.Fatalf("expected old remote node to be removed, ok=%v err=%v", ok, err)
	}
	if got, ok, err := store.GetNode(newRemote.GetHash()); err != nil || !ok || got.GetGroup() != "remote-group" || got.GetOrigin() != pn.Origin_remote {
		t.Fatalf("expected new remote node normalized by replace, got=%v ok=%v err=%v", got, ok, err)
	}
}

func TestSqliteNodeStoreUseContractOnlyNode(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store := NewSqliteNodeStore(paths.PathGenerator.State(dir))
	protocol, err := contractnode.NewProtocol("direct", nil)
	if err != nil {
		t.Fatalf("create protocol failed: %v", err)
	}
	input := contractnode.Node{
		ID:      "contract-only",
		Name:    "contract-only-node",
		Group:   "manual",
		Origin:  "manual",
		Enabled: true,
		Chain:   []contractnode.Protocol{protocol},
	}
	if err := store.SaveContractNode(input); err != nil {
		t.Fatalf("save contract node failed: %v", err)
	}
	if err := store.UsePoint(input.ID); err != nil {
		t.Fatalf("use contract node failed: %v", err)
	}
	got, ok, err := store.GetContractNow(true)
	if err != nil {
		t.Fatalf("get selected tcp contract node failed: %v", err)
	}
	if !ok || got.ID != input.ID {
		t.Fatalf("selected tcp node = %+v ok=%v, want %q", got, ok, input.ID)
	}
	got, ok, err = store.GetContractNow(false)
	if err != nil {
		t.Fatalf("get selected udp contract node failed: %v", err)
	}
	if !ok || got.ID != input.ID {
		t.Fatalf("selected udp node = %+v ok=%v, want %q", got, ok, input.ID)
	}
}
