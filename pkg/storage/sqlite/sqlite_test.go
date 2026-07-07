package sqlite

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenBootstrapsEmptyDatabase(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")

	store, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("open sqlite store failed: %v", err)
	}
	defer func() { _ = store.Close() }()

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("state.db was not created: %v", err)
	}

	if got := queryInt(t, store.DB(), `PRAGMA foreign_keys`); got != 1 {
		t.Fatalf("foreign_keys pragma = %d, want 1", got)
	}

	for _, name := range []string{
		"metadata",
		"migrate",
		"android_extra_preferences",
		"settings_kv",
		"dns_settings",
		"dns_resolvers",
		"inbound_settings",
		"inbounds",
		"nodes",
		"nodes_fts",
		"node_tags",
		"subscriptions",
		"publishes",
		"route_settings",
		"route_rules",
		"route_lists",
		"route_list_refresh",
		"backup_settings",
		"statistics_kv",
		"traffic_hourly",
		"connection_sessions",
		"connection_history",
		"failed_connection_history",
	} {
		if !schemaObjectExists(t, store.DB(), name) {
			t.Fatalf("schema object %q was not created", name)
		}
	}

	if got := queryString(t, store.DB(), `SELECT value FROM metadata WHERE key = 'schema_version'`); got != "1" {
		t.Fatalf("metadata schema_version = %q, want 1", got)
	}

	if got := queryInt(t, store.DB(), `SELECT COUNT(*) FROM migrate`); got != int64(len(migrations)) {
		t.Fatalf("migrate row count = %d, want %d", got, len(migrations))
	}
}

func TestOpenIsIdempotent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")

	first, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("first open failed: %v", err)
	}
	_ = first.Close()

	second, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("second open failed: %v", err)
	}
	defer func() { _ = second.Close() }()

	if got := queryInt(t, second.DB(), `SELECT COUNT(*) FROM migrate WHERE version = 1`); got != 1 {
		t.Fatalf("migration version 1 count = %d, want 1", got)
	}
}

func TestOpenSharesDatabasePerPath(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")

	first, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("first open failed: %v", err)
	}
	second, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("second open failed: %v", err)
	}

	if first.DB() != second.DB() {
		t.Fatal("expected opens for the same path to share one *sql.DB")
	}

	key, err := canonicalPath(path)
	if err != nil {
		t.Fatalf("canonical path failed: %v", err)
	}

	sharedSQLite.Lock()
	refs := sharedSQLite.stores[key].refs
	sharedSQLite.Unlock()
	if refs != 2 {
		t.Fatalf("shared refs = %d, want 2", refs)
	}

	if err := first.Close(); err != nil {
		t.Fatalf("first close failed: %v", err)
	}
	if got := queryInt(t, second.DB(), `SELECT COUNT(*) FROM migrate`); got == 0 {
		t.Fatal("second handle stopped working after closing first handle")
	}

	sharedSQLite.Lock()
	refs = sharedSQLite.stores[key].refs
	sharedSQLite.Unlock()
	if refs != 1 {
		t.Fatalf("shared refs after first close = %d, want 1", refs)
	}

	if err := second.Close(); err != nil {
		t.Fatalf("second close failed: %v", err)
	}

	sharedSQLite.Lock()
	_, exists := sharedSQLite.stores[key]
	sharedSQLite.Unlock()
	if exists {
		t.Fatal("shared sqlite store was not released after the last close")
	}
}

func schemaObjectExists(t *testing.T, db *sql.DB, name string) bool {
	t.Helper()

	var count int64
	err := db.QueryRow(`
		SELECT COUNT(*)
		FROM sqlite_master
		WHERE name = ?
	`, name).Scan(&count)
	if err != nil {
		t.Fatalf("query sqlite_master for %q failed: %v", name, err)
	}

	return count > 0
}

func queryInt(t *testing.T, db *sql.DB, query string, args ...any) int64 {
	t.Helper()

	var value int64
	if err := db.QueryRow(query, args...).Scan(&value); err != nil {
		t.Fatalf("query %q failed: %v", query, err)
	}

	return value
}

func queryString(t *testing.T, db *sql.DB, query string, args ...any) string {
	t.Helper()

	var value string
	if err := db.QueryRow(query, args...).Scan(&value); err != nil {
		t.Fatalf("query %q failed: %v", query, err)
	}

	return value
}
