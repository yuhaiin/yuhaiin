package sqlite

import (
	"bytes"
	"compress/gzip"
	"database/sql"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// These databases were migrated and written by the previous application with
// each former driver. Opening them exercises the complete existing schema,
// including migrations, indexes, triggers and the two database kinds.
func TestLegacyDriverDatabases(t *testing.T) {
	for _, backend := range []string{"modernc", "mattn"} {
		for _, kind := range []string{"configuration", "management"} {
			t.Run(backend+"/"+kind, func(t *testing.T) {
				input, err := os.Open(filepath.Join("testdata", "legacy", backend+"-"+kind+".db.gz"))
				if err != nil {
					t.Fatal(err)
				}
				defer input.Close()
				compressed, err := gzip.NewReader(input)
				if err != nil {
					t.Fatal(err)
				}
				defer compressed.Close()
				path := filepath.Join(t.TempDir(), "legacy.db")
				output, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
				if err != nil {
					t.Fatal(err)
				}
				_, copyErr := io.Copy(output, compressed)
				closeErr := output.Close()
				if copyErr != nil {
					t.Fatal(copyErr)
				}
				if closeErr != nil {
					t.Fatal(closeErr)
				}
				opener := Open
				if kind == "management" {
					opener = OpenManagement
				}
				store, err := opener(t.Context(), path)
				if err != nil {
					t.Fatal(err)
				}
				defer store.Close()
				checkLegacyValues(t, store.DB())
				var integrity string
				if err := store.DB().QueryRowContext(t.Context(), "PRAGMA integrity_check").Scan(&integrity); err != nil || integrity != "ok" {
					t.Fatalf("integrity: %q, %v", integrity, err)
				}
				catalog, err := InspectStoreCatalog(t.Context(), path, kind)
				if err != nil || len(catalog) == 0 {
					t.Fatalf("live WAL catalog: %v", err)
				}
				if _, err := store.DB().ExecContext(t.Context(), "INSERT INTO metadata(key,value) VALUES('native_roundtrip',?)", []byte{1, 0, 2}); err != nil {
					t.Fatal(err)
				}
				snapshot := filepath.Join(t.TempDir(), "snapshot.db")
				if _, err := store.DB().ExecContext(t.Context(), "VACUUM INTO ?", snapshot); err != nil {
					t.Fatal(err)
				}
				if _, err := InspectBackupSnapshot(t.Context(), snapshot, kind); err != nil {
					t.Fatal(err)
				}
				reader, err := OpenSnapshotReader(t.Context(), snapshot)
				if err != nil {
					t.Fatal(err)
				}
				checkLegacyValues(t, reader)
				if _, err := reader.ExecContext(t.Context(), "DELETE FROM metadata"); err == nil {
					t.Fatal("snapshot reader accepted a write")
				}
				if err := reader.Close(); err != nil {
					t.Fatal(err)
				}
				if err := store.Close(); err != nil {
					t.Fatal(err)
				}
				reopened, err := opener(t.Context(), path)
				if err != nil {
					t.Fatal(err)
				}
				defer reopened.Close()
				checkLegacyValues(t, reopened.DB())
				var value []byte
				if err := reopened.DB().QueryRowContext(t.Context(), "SELECT value FROM metadata WHERE key='native_roundtrip'").Scan(&value); err != nil || !bytes.Equal(value, []byte{1, 0, 2}) {
					t.Fatalf("persisted write: %v, %v", value, err)
				}
			})
		}
	}
}

func checkLegacyValues(t *testing.T, db *sql.DB) {
	t.Helper()
	var text string
	var blob, empty []byte
	var kind string
	if err := db.QueryRowContext(t.Context(), "SELECT value FROM metadata WHERE key='fixture_text'").Scan(&text); err != nil {
		t.Fatal(err)
	}
	if text != "历史配置\x00SQLite🌍" {
		t.Fatalf("text: %q", text)
	}
	if err := db.QueryRowContext(t.Context(), "SELECT value FROM metadata WHERE key='fixture_blob'").Scan(&blob); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(blob, []byte{0, 255, 128, 7}) {
		t.Fatalf("blob: %v", blob)
	}
	if err := db.QueryRowContext(t.Context(), "SELECT value,typeof(value) FROM metadata WHERE key='fixture_empty_blob'").Scan(&empty, &kind); err != nil {
		t.Fatal(err)
	}
	if len(empty) != 0 || kind != "blob" {
		t.Fatalf("empty blob: %v %q", empty, kind)
	}
}
