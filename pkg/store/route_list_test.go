package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func TestRouteListStoreSaveListGetDelete(t *testing.T) {
	ctx := context.Background()
	sqliteStore, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sqliteStore.Close() }()

	store := NewRouteListStore(sqliteStore.DB())
	input := contractroute.RouteListDetail{
		Name:   "direct-host",
		Type:   "host",
		Source: contractroute.ListSource{Type: "local", Local: &contractroute.LocalSource{Lists: []string{"example.com"}}},
	}
	if err := store.SaveRouteList(ctx, input, 123); err != nil {
		t.Fatal(err)
	}
	items, err := store.ListRouteLists(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Name != "direct-host" || items[0].ItemCount != 1 || items[0].Preview != "example.com" {
		t.Fatalf("items = %+v", items)
	}
	got, err := store.GetRouteList(ctx, "direct-host")
	if err != nil {
		t.Fatal(err)
	}
	if got.Source.Local == nil || got.Source.Local.Lists[0] != "example.com" {
		t.Fatalf("detail = %+v", got)
	}
	if err := store.DeleteRouteList(ctx, "direct-host"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetRouteList(ctx, "direct-host"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetRouteList after delete error = %v", err)
	}
}
