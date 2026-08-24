package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestExportRustSnapshotRemovesDerivedFTSWithoutChangingSource(t *testing.T) {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	cacheDir = filepath.Join(cacheDir, "yuhaiin-rust-check")
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		t.Fatal(err)
	}
	base := fmt.Sprintf("rust-export-test-%d", time.Now().UnixNano())
	sourcePath := filepath.Join(cacheDir, base+"-source.sqlite")
	outputPath := filepath.Join(cacheDir, base+"-output.sqlite")
	t.Cleanup(func() {
		for _, path := range []string{
			sourcePath,
			outputPath,
			outputPath + ".manifest.json",
			outputPath + "-wal",
			outputPath + "-shm",
		} {
			_ = os.Remove(path)
		}
	})

	db, err := sql.Open(driverName, sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	for _, statement := range []string{
		`CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
		`INSERT INTO metadata(key, value) VALUES ('schema_version', '5')`,
		`CREATE TABLE fakeip_entries(id INTEGER PRIMARY KEY, domain TEXT NOT NULL)`,
		`INSERT INTO fakeip_entries(id, domain) VALUES (1, 'probe.example')`,
		`CREATE TABLE nodes(id INTEGER PRIMARY KEY, name TEXT NOT NULL)`,
		`INSERT INTO nodes(id, name) VALUES (1, 'probe')`,
		`CREATE VIRTUAL TABLE nodes_fts USING fts5(name, content='nodes', content_rowid='id')`,
		`INSERT INTO nodes_fts(rowid, name) VALUES (1, 'probe')`,
	} {
		if _, err := db.Exec(statement); err != nil {
			_ = db.Close()
			t.Fatalf("setup source with %q: %v", statement, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	report, err := ExportRustSnapshot(context.Background(), sourcePath, outputPath)
	if err != nil {
		t.Fatalf("export Rust snapshot: %v", err)
	}
	if report.SchemaVersion != "5" {
		t.Fatalf("schema version = %q, want 5", report.SchemaVersion)
	}
	if len(report.RemovedVirtualTables) != 1 || report.RemovedVirtualTables[0] != "nodes_fts" {
		t.Fatalf("removed virtual tables = %v, want [nodes_fts]", report.RemovedVirtualTables)
	}
	if report.FakeIPRows != 1 {
		t.Fatalf("exported FakeIP rows = %d, want 1", report.FakeIPRows)
	}
	if report.OutputBytes <= 0 {
		t.Fatalf("exported output size = %d, want positive size", report.OutputBytes)
	}
	if len(report.SnapshotSHA256) != 64 {
		t.Fatalf("exported snapshot SHA-256 = %q, want 64 hex characters", report.SnapshotSHA256)
	}
	if report.ManifestPath != outputPath+".manifest.json" {
		t.Fatalf("manifest path = %q, want %q", report.ManifestPath, outputPath+".manifest.json")
	}
	manifestBytes, err := os.ReadFile(report.ManifestPath)
	if err != nil {
		t.Fatalf("read snapshot manifest: %v", err)
	}
	var manifest RustSnapshotManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode snapshot manifest: %v", err)
	}
	if manifest.FormatVersion != rustSnapshotFormatVersion || manifest.Tool != rustSnapshotTool {
		t.Fatalf("manifest identity = %#v, want format %d/tool %q", manifest, rustSnapshotFormatVersion, rustSnapshotTool)
	}
	if manifest.SnapshotSHA256 != report.SnapshotSHA256 || manifest.SnapshotBytes != report.OutputBytes {
		t.Fatalf("manifest content metadata = %#v, want hash=%s bytes=%d", manifest, report.SnapshotSHA256, report.OutputBytes)
	}

	checkDB, err := sql.Open(driverName, outputPath)
	if err != nil {
		t.Fatal(err)
	}
	checkDB.SetMaxOpenConns(1)
	defer checkDB.Close()
	if got := queryString(t, checkDB, "PRAGMA quick_check"); got != "ok" {
		t.Fatalf("exported quick_check = %q, want ok", got)
	}
	if got := queryInt(t, checkDB, "SELECT COUNT(*) FROM nodes"); got != 1 {
		t.Fatalf("exported nodes = %d, want 1", got)
	}
	if schemaObjectExists(t, checkDB, "nodes_fts") {
		t.Fatal("exported snapshot still contains derived nodes_fts")
	}

	sourceCheck, err := sql.Open(driverName, sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	sourceCheck.SetMaxOpenConns(1)
	defer sourceCheck.Close()
	if !schemaObjectExists(t, sourceCheck, "nodes_fts") {
		t.Fatal("source snapshot was modified by export")
	}
	if got := queryInt(t, sourceCheck, "SELECT COUNT(*) FROM nodes"); got != 1 {
		t.Fatalf("source nodes = %d, want 1", got)
	}
}

func TestExportRustSnapshotRejectsExistingOutput(t *testing.T) {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	cacheDir = filepath.Join(cacheDir, "yuhaiin-rust-check")
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		t.Fatal(err)
	}
	base := fmt.Sprintf("rust-export-existing-%d", time.Now().UnixNano())
	sourcePath := filepath.Join(cacheDir, base+"-source.sqlite")
	outputPath := filepath.Join(cacheDir, base+"-output.sqlite")
	for _, path := range []string{sourcePath, outputPath} {
		if err := os.WriteFile(path, []byte("placeholder"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_ = os.Remove(sourcePath)
		_ = os.Remove(outputPath)
		_ = os.Remove(outputPath + ".manifest.json")
	})

	if _, err := ExportRustSnapshot(context.Background(), sourcePath, outputPath); err == nil {
		t.Fatal("export unexpectedly overwrote an existing output")
	}
}
