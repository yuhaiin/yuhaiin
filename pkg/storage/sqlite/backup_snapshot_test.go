package sqlite

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInspectBackupSnapshotWALAndSchema(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "state.db")
	store, err := Open(t.Context(), source)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.DB().ExecContext(t.Context(), "INSERT INTO metadata(key,value) VALUES('wal_fixture','committed in WAL')"); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectBackupSnapshot(t.Context(), source, "configuration"); err == nil {
		t.Fatal("live WAL main file accepted as standalone backup")
	}
	snapshot := filepath.Join(directory, "snapshot.db")
	if _, err := store.DB().ExecContext(t.Context(), "VACUUM INTO ?", snapshot); err != nil {
		t.Fatal(err)
	}
	version, err := InspectBackupSnapshot(t.Context(), snapshot, "configuration")
	if err != nil || version != configurationChangesMigration.Version {
		t.Fatalf("snapshot inspection: %d, %v", version, err)
	}
	opened, err := Open(t.Context(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var value string
	if err := opened.DB().QueryRowContext(t.Context(), "SELECT value FROM metadata WHERE key='wal_fixture'").Scan(&value); err != nil || value != "committed in WAL" {
		t.Fatal("snapshot lost committed WAL content")
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectBackupSnapshot(t.Context(), snapshot, "management"); err == nil {
		t.Fatal("configuration accepted as management database")
	}
	data, err := os.ReadFile(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	broken := filepath.Join(directory, "broken.db")
	if err := os.WriteFile(broken, data[:len(data)/2], 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectBackupSnapshot(t.Context(), broken, "configuration"); err == nil {
		t.Fatal("truncated database accepted")
	}
}

func TestInspectBackupSnapshotDoesNotMigrateUnknownFutureOrIncompleteSchema(t *testing.T) {
	for _, change := range []string{
		"INSERT INTO migrate(version,name,applied_at) VALUES(10000,'future',1); UPDATE metadata SET value='10000' WHERE key='schema_version'",
		"UPDATE migrate SET name='foreign schema' WHERE version=1",
		"DELETE FROM migrate WHERE version=10",
		"UPDATE metadata SET value='19' WHERE key='schema_version'",
		"DROP TABLE settings_json",
		"DROP TABLE certificate_acme_accounts",
		"DROP TABLE migrate; CREATE VIEW migrate AS SELECT 1 AS version, 'foreign' AS name",
		"PRAGMA foreign_keys=OFF; CREATE TABLE recovery_fk_parent(id INTEGER PRIMARY KEY); CREATE TABLE recovery_fk_child(id INTEGER REFERENCES recovery_fk_parent(id)); INSERT INTO recovery_fk_child(id) VALUES(1)",
	} {
		t.Run(change, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.db")
			db, err := Open(t.Context(), path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.DB().ExecContext(t.Context(), change); err != nil {
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := InspectBackupSnapshot(t.Context(), path, "configuration"); err == nil {
				t.Fatal("incompatible schema accepted")
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(before) != string(after) {
				t.Fatal("inspection modified or migrated archive database")
			}
		})
	}
}

func TestBackupSnapshotLimitsAreConnectionLocal(t *testing.T) {
	restricted, err := sql.Open(driverName, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer restricted.Close()
	conn, err := restricted.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := restrictBackupSnapshot(conn); err != nil {
		t.Fatal(err)
	}
	var length int
	if err := conn.QueryRowContext(t.Context(), "SELECT length(zeroblob(68157440))").Scan(&length); err == nil {
		t.Fatal("snapshot accepted a value over 64 MiB")
	}
	if _, err := conn.ExecContext(t.Context(), strings.Repeat(" ", 1<<20)+"SELECT 1"); err == nil {
		t.Fatal("snapshot accepted SQL over 1 MiB")
	}
	ordinary, err := sql.Open(driverName, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer ordinary.Close()
	if err := ordinary.QueryRowContext(t.Context(), "SELECT length(zeroblob(68157440))").Scan(&length); err != nil || length != 68157440 {
		t.Fatalf("snapshot restrictions changed ordinary connections: %d, %v", length, err)
	}
}
