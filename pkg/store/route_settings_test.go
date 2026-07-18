package store

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func TestRouteSettingsStoreSettings(t *testing.T) {
	ctx := context.Background()
	sqliteStore, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sqliteStore.Close() }()

	store := NewRouteSettingsStore(sqliteStore.DB())
	input := RouteSettings{
		DirectResolver: "direct",
		ProxyResolver:  "proxy",
		ResolveLocally: true,
		UDPProxyFQDN:   1,
	}
	if err := store.SaveSettings(ctx, input); err != nil {
		t.Fatal(err)
	}
	got, err := store.Settings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got != input {
		t.Fatalf("settings = %+v, want %+v", got, input)
	}
}

func TestRouteSettingsStoreListSettings(t *testing.T) {
	ctx := context.Background()
	sqliteStore, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sqliteStore.Close() }()

	store := NewRouteSettingsStore(sqliteStore.DB())
	input := RouteListSettings{
		RefreshInterval:      3600,
		LastRefreshTime:      123,
		Error:                "last error",
		HostIndexDisk:        true,
		MaxMindDBDownloadURL: "https://example.com/geo.mmdb",
		MaxMindDBError:       "geo error",
	}
	if err := store.SaveListSettings(ctx, input); err != nil {
		t.Fatal(err)
	}
	got, err := store.ListSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got != input {
		t.Fatalf("list settings = %+v, want %+v", got, input)
	}
}
