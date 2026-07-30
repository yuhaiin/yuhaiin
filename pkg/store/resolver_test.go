package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func TestResolverStoreSaveListGetDelete(t *testing.T) {
	ctx := context.Background()
	sqliteStore, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sqliteStore.Close() }()

	store := NewResolverStore(sqliteStore.DB())
	input := contractresolver.Resolver{ID: "ali", Type: "udp", Host: "223.5.5.5:53", Subnet: "1.1.1.0/24"}
	if err := store.Save(ctx, input, 123); err != nil {
		t.Fatal(err)
	}
	list, err := store.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != "ali" || list[0].Host != "223.5.5.5:53" {
		t.Fatalf("resolvers = %+v", list)
	}
	got, err := store.Get(ctx, "ali")
	if err != nil {
		t.Fatal(err)
	}
	if got.Subnet != "1.1.1.0/24" {
		t.Fatalf("resolver = %+v", got)
	}
	if err := store.Delete(ctx, "ali"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, "ali"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after delete error = %v", err)
	}
}

func TestResolverStoreListPageUsesDatabasePaginationAndQuery(t *testing.T) {
	ctx := context.Background()
	sqliteStore, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sqliteStore.Close() }()

	store := NewResolverStore(sqliteStore.DB())
	for _, resolver := range []contractresolver.Resolver{
		{ID: "resolver-a", Type: "udp", Host: "223.5.5.5:53"},
		{ID: "resolver-b", Type: "dot", Host: "1.1.1.1:853", Subnet: "2001:db8::/32"},
	} {
		if err := store.Save(ctx, resolver, 123); err != nil {
			t.Fatal(err)
		}
	}

	items, total, err := store.ListPage(ctx, "", 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(items) != 1 || items[0].ID != "resolver-b" {
		t.Fatalf("page = %+v, total = %d", items, total)
	}
	items, total, err = store.ListPage(ctx, "2001:db8", 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(items) != 1 || items[0].ID != "resolver-b" {
		t.Fatalf("query page = %+v, total = %d", items, total)
	}
}
