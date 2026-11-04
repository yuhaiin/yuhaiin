package sqlite

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestInspectStoreCatalogReadsLiveWALWithoutMigrating(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.DB().ExecContext(t.Context(), "PRAGMA wal_checkpoint(TRUNCATE); PRAGMA wal_autocheckpoint=0"); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := InspectStoreCatalog(t.Context(), path, "configuration")
	if err != nil || len(catalog) != len(migrations) {
		t.Fatal("actual schema unavailable", err)
	}
	if _, err := db.DB().ExecContext(t.Context(), "UPDATE metadata SET value='999' WHERE key='schema_version'"); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("fixture did not retain its update exclusively in WAL", err)
	}
	if _, err := InspectStoreCatalog(t.Context(), path, "configuration"); !errors.Is(err, ErrIncompatibleSchema) {
		t.Fatal("schema inspection ignored live WAL", err)
	}
	var value string
	if err := db.DB().QueryRowContext(t.Context(), "SELECT value FROM metadata WHERE key='schema_version'").Scan(&value); err != nil || value != "999" {
		t.Fatal("inspection mutated the database", err, value)
	}
}
