package migrate

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func TestStateDBRequiresInitialization(t *testing.T) {
	ctx := t.Context()
	state := NewStateDB(filepath.Join(t.TempDir(), "state.db"))
	defer func() { _ = state.Close() }()
	if _, err := state.SQLDB(ctx); err == nil || !strings.Contains(err.Error(), "call Migrate") {
		t.Fatalf("SQLDB before Migrate: %v", err)
	}
	if err := state.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := state.Migrate(ctx); err != nil {
		t.Fatalf("repeat initialization failed: %v", err)
	}
	db, err := state.SQLDB(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var version string
	if err := db.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key = 'schema_version'").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version == "" {
		t.Fatal("schema migrations were not applied")
	}
}

func TestStateDBPreservesExistingSQLiteData(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "state.db")
	store, err := storagesqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx,
		"INSERT INTO settings_kv(section, key, value_json, updated_at) VALUES ('general','ipv6','true',1)"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx,
		"INSERT INTO android_extra_preferences(key, value_json, updated_at) VALUES ('test','123',1)"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	state := NewStateDB(path)
	if err := state.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	db, err := state.SQLDB(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for query, want := range map[string]string{
		"SELECT value_json FROM settings_kv WHERE section='general' AND key='ipv6'": "true",
		"SELECT value_json FROM android_extra_preferences WHERE key='test'":         "123",
	} {
		var value string
		if err := db.QueryRowContext(ctx, query).Scan(&value); err != nil || value != want {
			t.Fatalf("%s: got %q, err %v, want %q", query, value, err, want)
		}
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatalf("double close: %v", err)
	}
}

func TestStateDBRejectsEmptyPath(t *testing.T) {
	state := NewStateDB("")
	defer func() { _ = state.Close() }()
	if err := state.Migrate(context.Background()); err == nil {
		t.Fatal("expected an error for an empty state path")
	}
}
