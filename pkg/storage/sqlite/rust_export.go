package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	rustSnapshotFormatVersion = 1
	rustSnapshotTool          = "yuhaiin-rust-export"
	rustSnapshotToolVersion   = "1"
)

// RustSnapshotManifest is written next to an exported snapshot. The Rust
// installer verifies the byte length and SHA-256 before copying the file, so
// a partially copied or stale snapshot fails closed.
type RustSnapshotManifest struct {
	FormatVersion        int      `json:"format_version"`
	Tool                 string   `json:"tool"`
	ToolVersion          string   `json:"tool_version"`
	SourceSchemaVersion  string   `json:"source_schema_version"`
	SnapshotSHA256       string   `json:"snapshot_sha256"`
	SnapshotBytes        int64    `json:"snapshot_bytes"`
	FakeIPRows           int64    `json:"fakeip_rows"`
	RemovedVirtualTables []string `json:"removed_virtual_tables"`
}

// RustSnapshotReport describes the durable parts of a Go SQLite snapshot that
// was copied for the pure-Rust importer.  FTS5 indexes are derived from the
// plain tables and are deliberately omitted from the output.
type RustSnapshotReport struct {
	SchemaVersion        string
	RemovedVirtualTables []string
	FakeIPRows           int64
	OutputBytes          int64
	SnapshotSHA256       string
	ManifestPath         string
}

// ExportRustSnapshot creates a consistent, standalone copy of sourcePath and
// removes every FTS5 virtual table from the copy.  The source is opened for a
// read snapshot and is never altered.  The output is suitable for
// yuhaiin-rust's SQLite importer, which intentionally receives an FTS-free
// snapshot because the FTS5 shadow
// index format emitted by some production Go/SQLite versions.
//
// The caller should stop writers to the source for the duration of the
// export, or otherwise arrange the same consistent snapshot boundary used by
// the application's backup path.  outputPath must not already exist; this
// avoids silently overwriting a previous migration artifact.
func ExportRustSnapshot(ctx context.Context, sourcePath, outputPath string) (RustSnapshotReport, error) {
	var report RustSnapshotReport
	if sourcePath == "" || outputPath == "" {
		return report, errors.New("source and output SQLite paths are required")
	}
	sourcePath, err := filepath.Abs(filepath.Clean(sourcePath))
	if err != nil {
		return report, fmt.Errorf("resolve source SQLite path: %w", err)
	}
	outputPath, err = filepath.Abs(filepath.Clean(outputPath))
	if err != nil {
		return report, fmt.Errorf("resolve output SQLite path: %w", err)
	}
	if sourcePath == outputPath {
		return report, errors.New("source and output SQLite paths must differ")
	}
	if _, err := os.Stat(sourcePath); err != nil {
		return report, fmt.Errorf("stat source SQLite path: %w", err)
	}
	if _, err := os.Stat(outputPath); err == nil {
		return report, fmt.Errorf("refusing to overwrite existing output %s", outputPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return report, fmt.Errorf("stat output SQLite path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return report, fmt.Errorf("create output SQLite directory: %w", err)
	}
	manifestPath := outputPath + ".manifest.json"
	if _, err := os.Stat(manifestPath); err == nil {
		return report, fmt.Errorf("refusing to overwrite existing snapshot manifest %s", manifestPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return report, fmt.Errorf("stat snapshot manifest path: %w", err)
	}

	source, err := sql.Open(driverName, sourcePath)
	if err != nil {
		return report, fmt.Errorf("open source SQLite snapshot: %w", err)
	}
	source.SetMaxOpenConns(1)
	sourceClosed := false
	defer func() {
		if !sourceClosed {
			_ = source.Close()
		}
	}()
	if err := source.PingContext(ctx); err != nil {
		return report, fmt.Errorf("ping source SQLite snapshot: %w", err)
	}
	if _, err := source.ExecContext(ctx, "PRAGMA busy_timeout = 5000"); err != nil {
		return report, fmt.Errorf("configure source SQLite snapshot: %w", err)
	}
	if err := source.QueryRowContext(ctx, `
		SELECT COALESCE((SELECT value FROM metadata WHERE key = 'schema_version'), '')
	`).Scan(&report.SchemaVersion); err != nil {
		return report, fmt.Errorf("read Go schema version: %w", err)
	}

	// VACUUM INTO obtains a consistent read snapshot, includes WAL-visible
	// committed rows, and writes only the new output file.
	if _, err := source.ExecContext(
		ctx,
		"VACUUM INTO '"+rustSnapshotSqliteStringLiteral(outputPath)+"'",
	); err != nil {
		return report, fmt.Errorf("copy consistent SQLite snapshot: %w", err)
	}
	if err := source.Close(); err != nil {
		return report, fmt.Errorf("close source SQLite snapshot: %w", err)
	}
	sourceClosed = true

	destination, err := sql.Open(driverName, outputPath)
	if err != nil {
		return report, fmt.Errorf("open Rust SQLite snapshot: %w", err)
	}
	destination.SetMaxOpenConns(1)
	defer destination.Close()
	if err := destination.PingContext(ctx); err != nil {
		return report, fmt.Errorf("ping Rust SQLite snapshot: %w", err)
	}

	tx, err := destination.BeginTx(ctx, nil)
	if err != nil {
		return report, fmt.Errorf("begin FTS export cleanup transaction: %w", err)
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT name
		FROM sqlite_master
		WHERE type = 'table'
		  AND lower(COALESCE(sql, '')) LIKE '%using fts5%'
		ORDER BY name
	`)
	if err != nil {
		_ = tx.Rollback()
		return report, fmt.Errorf("list FTS5 tables in export: %w", err)
	}
	var virtualTables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			_ = rows.Close()
			_ = tx.Rollback()
			return report, fmt.Errorf("read FTS5 table name in export: %w", err)
		}
		virtualTables = append(virtualTables, name)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		_ = tx.Rollback()
		return report, fmt.Errorf("iterate FTS5 tables in export: %w", err)
	}
	if err := rows.Close(); err != nil {
		_ = tx.Rollback()
		return report, fmt.Errorf("close FTS5 table query: %w", err)
	}
	sort.Strings(virtualTables)
	for _, table := range virtualTables {
		if _, err := tx.ExecContext(ctx, `DROP TABLE "`+strings.ReplaceAll(table, `"`, `""`)+`"`); err != nil {
			_ = tx.Rollback()
			return report, fmt.Errorf("drop derived FTS5 table %q: %w", table, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return report, fmt.Errorf("commit FTS export cleanup: %w", err)
	}
	report.RemovedVirtualTables = virtualTables

	var quickCheck string
	if err := destination.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&quickCheck); err != nil {
		return report, fmt.Errorf("check exported SQLite snapshot: %w", err)
	}
	if quickCheck != "ok" {
		return report, fmt.Errorf("exported SQLite snapshot quick_check = %q", quickCheck)
	}
	if err := destination.QueryRowContext(ctx, `
		SELECT COALESCE((SELECT COUNT(*) FROM fakeip_entries), 0)
	`).Scan(&report.FakeIPRows); err != nil {
		return report, fmt.Errorf("count exported FakeIP rows: %w", err)
	}
	if err := destination.Close(); err != nil {
		return report, fmt.Errorf("close exported SQLite snapshot: %w", err)
	}
	if info, err := os.Stat(outputPath); err == nil {
		report.OutputBytes = info.Size()
	} else {
		return report, fmt.Errorf("stat exported SQLite snapshot: %w", err)
	}
	if report.SnapshotSHA256, err = rustSnapshotSHA256(outputPath); err != nil {
		return report, fmt.Errorf("hash exported SQLite snapshot: %w", err)
	}
	manifest := RustSnapshotManifest{
		FormatVersion:       rustSnapshotFormatVersion,
		Tool:                rustSnapshotTool,
		ToolVersion:         rustSnapshotToolVersion,
		SourceSchemaVersion: report.SchemaVersion,
		SnapshotSHA256:      report.SnapshotSHA256,
		SnapshotBytes:       report.OutputBytes,
		FakeIPRows:          report.FakeIPRows,
		// Use an allocated empty slice so JSON encodes [] rather than null.
		// Rust accepts both for compatibility with snapshots produced before
		// this normalization.
		RemovedVirtualTables: append([]string{}, report.RemovedVirtualTables...),
	}
	if err := writeRustSnapshotManifest(manifestPath, manifest); err != nil {
		return report, fmt.Errorf("write Rust snapshot manifest: %w", err)
	}
	report.ManifestPath = manifestPath
	return report, nil
}

func rustSnapshotSqliteStringLiteral(value string) string {
	return strings.ReplaceAll(value, "'", "''")
}

func rustSnapshotSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func writeRustSnapshotManifest(path string, manifest RustSnapshotManifest) error {
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(encoded); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	remove = false
	return nil
}
