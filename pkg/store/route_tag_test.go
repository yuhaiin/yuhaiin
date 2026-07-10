package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

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
	if err := store.DeleteTag(ctx, "auto"); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteTag(ctx, "auto"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteTag missing error = %v", err)
	}
}
