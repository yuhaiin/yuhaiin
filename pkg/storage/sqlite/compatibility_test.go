package sqlite

import (
	"bytes"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenRejectsIncompatibleHistoryBeforeChangingDatabase(t *testing.T) {
	for _, fault := range []string{"future-configuration", "future-management", "foreign-name", "gap", "metadata-version", "configuration-as-management", "management-as-configuration"} {
		t.Run(fault, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "fixture.db")
			kind := "configuration"
			opener := Open
			if fault == "future-management" || fault == "management-as-configuration" {
				kind = "management"
				opener = OpenManagement
			}
			store, err := opener(t.Context(), path)
			if err != nil {
				t.Fatal(err)
			}
			statement := ""
			switch fault {
			case "future-configuration":
				statement = "INSERT INTO migrate(version,name,applied_at) VALUES(21,'future_schema',1); UPDATE metadata SET value='21' WHERE key='schema_version'"
			case "future-management":
				statement = "INSERT INTO migrate(version,name,applied_at) VALUES(6,'future_identity',1); UPDATE metadata SET value='6' WHERE key='schema_version'"
			case "foreign-name":
				statement = "UPDATE migrate SET name='foreign_schema' WHERE version=1"
			case "gap":
				statement = "DELETE FROM migrate WHERE version=10"
			case "metadata-version":
				statement = "UPDATE metadata SET value='19' WHERE key='schema_version'"
			case "configuration-as-management":
				opener = OpenManagement
			case "management-as-configuration":
				opener = Open
			}
			if statement != "" {
				if _, err := store.DB().ExecContext(t.Context(), statement); err != nil {
					t.Fatal(err)
				}
				if err := checkStoreCompatibility(t.Context(), store.DB(), kind); !errors.Is(err, ErrIncompatibleSchema) {
					t.Fatalf("incompatible direct bootstrap preflight: %v", err)
				}
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			opened, err := opener(t.Context(), path)
			if opened != nil {
				_ = opened.Close()
			}
			if !errors.Is(err, ErrIncompatibleSchema) || opened != nil {
				t.Fatalf("unsafe database was accepted: %v", err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("incompatible open changed database bytes")
			}
			for _, suffix := range []string{"-wal", "-shm", "-journal"} {
				if _, err := os.Stat(path + suffix); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("incompatible open changed journal mode or left a sidecar")
				}
			}
		})
	}
}

func TestBootstrapRejectsForeignObjectsAndRecoversEmptyBase(t *testing.T) {
	for _, fault := range []string{"foreign-table", "sqlite-prefix-table", "metadata-view", "unrecorded-objects", "empty-base"} {
		t.Run(fault, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "fixture.db")
			db, err := sql.Open(driverName, path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			switch fault {
			case "foreign-table":
				_, err = db.ExecContext(t.Context(), "CREATE TABLE foreign_owner(id INTEGER PRIMARY KEY)")
			case "sqlite-prefix-table":
				_, err = db.ExecContext(t.Context(), "CREATE TABLE sqliteXforeign(id INTEGER PRIMARY KEY)")
			case "metadata-view":
				_, err = db.ExecContext(t.Context(), "CREATE VIEW metadata AS SELECT 'schema_version' AS key,'20' AS value")
			default:
				err = bootstrapBase(t.Context(), db)
				if err == nil && fault == "unrecorded-objects" {
					_, err = db.ExecContext(t.Context(), "CREATE TABLE foreign_owner(id INTEGER PRIMARY KEY)")
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			var before int
			if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM sqlite_schema").Scan(&before); err != nil {
				t.Fatal(err)
			}
			err = Bootstrap(t.Context(), db)
			if fault == "empty-base" {
				if err != nil {
					t.Fatal("interrupted first bootstrap did not recover", err)
				}
				if count := queryInt(t, db, "SELECT count(*) FROM migrate"); count != int64(len(migrations)) {
					t.Fatal("known migrations were not applied")
				}
				return
			}
			if !errors.Is(err, ErrIncompatibleSchema) {
				t.Fatalf("foreign database accepted: %v", err)
			}
			if after := queryInt(t, db, "SELECT count(*) FROM sqlite_schema"); after != int64(before) {
				t.Fatal("bootstrap added objects to a foreign database")
			}
		})
	}
}
