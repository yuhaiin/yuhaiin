package store

import (
	"path/filepath"
	"strings"
	"testing"

	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func TestRouteRegistryStoreDefaultsAndCRUD(t *testing.T) {
	ctx := t.Context()
	sqliteStore, err := storagesqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer sqliteStore.Close()

	store := NewRouteRegistryStore(sqliteStore.DB())

	initial, err := store.ListRegistries(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(initial.Items) != 1 {
		t.Fatalf("initial registries = %+v", initial.Items)
	}
	kitte := initial.Items[0]
	if kitte.ID != DefaultRouteRegistryID || kitte.URL != DefaultRouteRegistryURL || !kitte.Enabled || !kitte.Builtin {
		t.Fatalf("default registry = %+v", kitte)
	}

	created, err := store.SaveRegistry(ctx, contractroute.Registry{
		Name:    "Community",
		URL:     "https://example.com/registry.json",
		Enabled: true,
	}, 123)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(created.ID, "registry-") || created.Builtin || !created.Enabled {
		t.Fatalf("created registry = %+v", created)
	}

	got, err := store.GetRegistry(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "Community" || got.URL != "https://example.com/registry.json" {
		t.Fatalf("registry = %+v", got)
	}

	got.Enabled = false
	got.Name = "Community Rules"
	updated, err := store.SaveRegistry(ctx, got, 124)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Enabled || updated.Name != "Community Rules" {
		t.Fatalf("updated registry = %+v", updated)
	}

	if err := store.DeleteRegistry(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteRegistry(ctx, DefaultRouteRegistryID); err == nil {
		t.Fatal("deleting built-in registry unexpectedly succeeded")
	}
}

func TestRouteRegistryStoreRejectsUnsupportedURL(t *testing.T) {
	ctx := t.Context()
	sqliteStore, err := storagesqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer sqliteStore.Close()

	store := NewRouteRegistryStore(sqliteStore.DB())
	_, err = store.SaveRegistry(ctx, contractroute.Registry{
		Name:    "Local",
		URL:     "file:///tmp/registry.json",
		Enabled: true,
	}, 0)
	if err == nil {
		t.Fatal("file registry URL unexpectedly accepted")
	}
}
