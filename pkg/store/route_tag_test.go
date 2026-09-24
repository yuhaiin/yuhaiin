package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func TestRouteTagStoreSaveListDelete(t *testing.T) {
	ctx := context.Background()
	sqliteStore, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sqliteStore.Close() }()

	store := NewRouteTagStore(sqliteStore.DB())
	if err := store.SaveTag(ctx, contractroute.TagItem{Name: "auto", Type: "node", Hash: []string{"node-a"}}, 123); err != nil {
		t.Fatal(err)
	}
	got, err := store.ListTags(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "auto" || got[0].Type != "node" || got[0].Hash[0] != "node-a" {
		t.Fatalf("tags = %+v", got)
	}
	runtimeTag, ok, err := NewNodeStore(sqliteStore.DB()).GetTag(ctx, "auto")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || runtimeTag.Kind != "node" || len(runtimeTag.TargetIDs) != 1 || runtimeTag.TargetIDs[0] != "node-a" {
		t.Fatalf("runtime tag = %+v, ok = %v", runtimeTag, ok)
	}
	usingIDs, err := NewNodeStore(sqliteStore.DB()).UsingIDs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(usingIDs) != 1 || usingIDs[0] != "node-a" {
		t.Fatalf("using node ids = %+v", usingIDs)
	}
	if err := store.DeleteTag(ctx, "auto"); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteTag(ctx, "auto"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteTag missing error = %v", err)
	}
}

func TestRouteTagStoreListsTagsReferencedByRules(t *testing.T) {
	ctx := context.Background()
	sqliteStore, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sqliteStore.Close() }()

	ruleStore := NewRouteRuleStore(sqliteStore.DB())
	if err := ruleStore.SaveRule(ctx, contractroute.RouteRule{Name: "remote", Mode: "proxy", Tag: "rule-tag"}, 0, 100); err != nil {
		t.Fatal(err)
	}

	tags, err := NewRouteTagStore(sqliteStore.DB()).ListTags(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(tags) != 1 || tags[0].Name != "rule-tag" || tags[0].Type != "node" || len(tags[0].Hash) != 0 {
		t.Fatalf("tags = %+v", tags)
	}

	tagStore := NewRouteTagStore(sqliteStore.DB())
	if err := tagStore.SaveTag(ctx, contractroute.TagItem{Name: "rule-tag", Type: "node", Hash: []string{"node-a"}}, 200); err != nil {
		t.Fatal(err)
	}
	tags, err = tagStore.ListTags(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(tags) != 1 || tags[0].Name != "rule-tag" || len(tags[0].Hash) != 1 || tags[0].Hash[0] != "node-a" {
		t.Fatalf("overridden tags = %+v", tags)
	}
	runtimeTag, ok, err := NewNodeStore(sqliteStore.DB()).GetTag(ctx, "rule-tag")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || len(runtimeTag.TargetIDs) != 1 || runtimeTag.TargetIDs[0] != "node-a" {
		t.Fatalf("runtime tag = %+v, ok = %v", runtimeTag, ok)
	}
}

func TestNodeStoreReadsLegacyTagWhenV2RowIsAbsent(t *testing.T) {
	ctx := context.Background()
	sqliteStore, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sqliteStore.Close() }()

	if _, err := sqliteStore.DB().ExecContext(ctx, `
		INSERT INTO node_tags(tag_name, target_kind, target_id, updated_at)
		VALUES ('legacy', 'node', 'node-a', 100)
	`); err != nil {
		t.Fatal(err)
	}
	got, ok, err := NewNodeStore(sqliteStore.DB()).GetTag(ctx, "legacy")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || got.Kind != "node" || len(got.TargetIDs) != 1 || got.TargetIDs[0] != "node-a" {
		t.Fatalf("legacy runtime tag = %+v, ok = %v", got, ok)
	}
	tags, err := NewRouteTagStore(sqliteStore.DB()).ListTags(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(tags) != 1 || tags[0].Name != "legacy" || len(tags[0].Hash) != 1 || tags[0].Hash[0] != "node-a" {
		t.Fatalf("legacy listed tags = %+v", tags)
	}
}

func TestNodeStoreTagLifecycleUsesCanonicalContract(t *testing.T) {
	ctx := context.Background()
	sqliteStore, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sqliteStore.Close() }()

	nodes := NewNodeStore(sqliteStore.DB())
	if err := nodes.AddTag(ctx, "runtime", "node", "node-a"); err != nil {
		t.Fatal(err)
	}
	if err := nodes.AddTag(ctx, "runtime", "node", "node-b"); err != nil {
		t.Fatal(err)
	}
	tag, ok, err := nodes.GetTag(ctx, "runtime")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || len(tag.TargetIDs) != 2 || tag.TargetIDs[0] != "node-a" || tag.TargetIDs[1] != "node-b" {
		t.Fatalf("runtime tag after add = %+v, ok = %v", tag, ok)
	}
	if err := nodes.DeleteTag(ctx, "runtime"); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := nodes.GetTag(ctx, "runtime"); err != nil || ok {
		t.Fatalf("runtime tag after delete = ok %v, err %v", ok, err)
	}

	protocol, err := contractnode.NewTypedProtocol(contractnode.Direct{})
	if err != nil {
		t.Fatal(err)
	}
	if err := nodes.Save(ctx, contractnode.Node{ID: "node-a", Name: "node-a", Group: "manual", Origin: "manual", Enabled: true, Chain: []contractnode.Protocol{protocol}}, 100); err != nil {
		t.Fatal(err)
	}
	if err := NewRouteTagStore(sqliteStore.DB()).SaveTag(ctx, contractroute.TagItem{Name: "cleanup", Type: "node", Hash: []string{"node-a"}}, 100); err != nil {
		t.Fatal(err)
	}
	if err := nodes.Delete(ctx, "node-a"); err != nil {
		t.Fatal(err)
	}
	stored, found, err := NewRouteTagStore(sqliteStore.DB()).GetTag(ctx, "cleanup")
	if err != nil {
		t.Fatal(err)
	}
	if !found || len(stored.Hash) != 0 {
		t.Fatalf("tag after node delete = %+v, found = %v", stored, found)
	}
}
