package sqlite

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestManagementDatabasePrivateSeparateAndIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "management.db")
	db, err := OpenManagement(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(t.Context(), path); err == nil {
		t.Fatal("configuration store accepted a live management database")
	}
	if _, err := db.DB().ExecContext(t.Context(), `INSERT INTO management_users(id,login,role,client_salt,credential,created_at,updated_at) VALUES('admin','admin','admin',randomblob(16),randomblob(32),1,1)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = OpenManagement(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if queryInt(t, db.DB(), `SELECT count(*) FROM management_users`) != 1 {
		t.Fatal("migration replaced identities")
	}
	if queryInt(t, db.DB(), `SELECT count(*) FROM migrate`) != 1 {
		t.Fatal("migration applied more than once")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("private database mode: %v", info.Mode())
	}
	config, err := Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer config.Close()
	if _, err := OpenManagement(t.Context(), config.Path()); err == nil {
		t.Fatal("management store accepted a live state database")
	}
	backup, err := ExportConfig(t.Context(), config.DB())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(backup, []byte("management_")) {
		t.Fatal("ordinary configuration export includes management identities")
	}
	if schemaObjectExists(t, config.DB(), "management_users") {
		t.Fatal("authentication table created in state database")
	}
}
