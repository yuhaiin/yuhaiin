package migrate

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/paths"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func TestImportLegacyNodesFromJSONRejectsMalformedFile(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := storagesqlite.Open(ctx, filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	path := paths.PathGenerator.Node(dir)
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}

	err = ImportLegacyNodesFromJSON(ctx, store.DB(), dir, 100)
	if err == nil {
		t.Fatal("malformed legacy node JSON was accepted")
	}
	if errors.Is(err, os.ErrNotExist) {
		t.Fatalf("malformed JSON was reported as missing: %v", err)
	}
	assertNoMigrationMarker(t, ctx, store.DB(), "legacy_node_import_done")
}

func assertNoMigrationMarker(t *testing.T, ctx context.Context, db interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, key string) {
	t.Helper()
	var value string
	err := db.QueryRowContext(ctx, `SELECT value FROM metadata WHERE key = ?`, key).Scan(&value)
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("migration marker %q = %q, err=%v", key, value, err)
	}
}
