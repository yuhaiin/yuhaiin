package sqlite

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// A database created before DNS history upgrades in place and keeps its data.
func TestDNSQueryHistoryMigrationFromPreviousSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := sql.Open(driverName, path)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	if err := configure(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	if err := bootstrapBase(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	for _, migration := range migrations {
		if migration.Version >= dnsQueryHistoryMigration.Version {
			break
		}
		if err := applyMigration(t.Context(), db, migration); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ExecContext(t.Context(), `INSERT INTO failed_connection_history(protocol, host, process_name, failed_count, last_seen_at, last_error) VALUES ('udp', 'kept.example:53', '', 1, 1, 'x')`); err != nil {
		t.Fatal(err)
	}
	if schemaObjectExists(t, db, "dns_query_history") {
		t.Fatal("previous schema already has DNS history")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, name := range []string{"dns_query_history", "dns_query_history_settings", "dns_query_history_created", "dns_query_history_domain", "dns_query_history_outcome"} {
		if !schemaObjectExists(t, store.DB(), name) {
			t.Fatalf("%s was not created", name)
		}
	}
	if queryInt(t, store.DB(), `SELECT COUNT(*) FROM failed_connection_history WHERE host = 'kept.example:53'`) != 1 {
		t.Fatal("existing history was lost")
	}
}
