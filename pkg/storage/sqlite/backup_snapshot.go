package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// InspectBackupSnapshot never bootstraps or migrates input. The archive must
// contain a standalone SQLite snapshot, not the main file of a live WAL store.
// Only a known, contiguous migration prefix of the requested store is accepted.
func InspectBackupSnapshot(ctx context.Context, path, kind string) (int, error) {
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Lstat(path + suffix); err == nil {
			return 0, errors.New("backup snapshot has live SQLite sidecars")
		} else if !errors.Is(err, os.ErrNotExist) {
			return 0, err
		}
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return 0, err
	}
	fileURL := &url.URL{Scheme: "file", Path: filepath.ToSlash(absolute), RawQuery: "mode=ro&immutable=1"}
	if filepath.VolumeName(absolute) != "" && !strings.HasPrefix(fileURL.Path, "/") {
		fileURL.Path = "/" + fileURL.Path
	}
	uri := fileURL.String()
	db, err := sql.Open(driverName, uri)
	if err != nil {
		return 0, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	conn, err := db.Conn(ctx)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	if err := restrictBackupSnapshot(conn); err != nil {
		return 0, err
	}
	for _, statement := range []string{"PRAGMA query_only=ON", "PRAGMA trusted_schema=OFF", "PRAGMA cache_size=-2048"} {
		if _, err := conn.ExecContext(ctx, statement); err != nil {
			return 0, err
		}
	}
	var check string
	if err := conn.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&check); err != nil {
		return 0, fmt.Errorf("read backup SQLite integrity: %w", err)
	}
	if check != "ok" {
		return 0, errors.New("backup SQLite integrity check failed")
	}
	known := migrations
	required := []string{"settings_json", "nodes_v2", "inbounds_v2", "gateway_configuration"}
	switch kind {
	case "configuration":
	case "management":
		known = []Migration{managementAuthMigration, managementInitializationMigration, proxyCredentialsMigration, managementOAuthMigration, managementAuditMigration}
		required = []string{"management_users", "management_credentials", "management_auth_setup"}
	default:
		return 0, errors.New("unknown backup SQLite store kind")
	}
	for _, table := range []string{"migrate", "metadata"} {
		var rootPage int
		if err := conn.QueryRowContext(ctx, "SELECT rootpage FROM sqlite_schema WHERE type='table' AND name=?", table).Scan(&rootPage); err != nil || rootPage < 1 {
			return 0, errors.New("backup schema metadata is not an ordinary table")
		}
	}
	rows, err := conn.QueryContext(ctx, "SELECT CASE WHEN typeof(version)='integer' THEN version ELSE -1 END, substr(name,1,256) FROM migrate ORDER BY version LIMIT ?", len(known)+1)
	if err != nil {
		return 0, err
	}
	count, last := 0, 0
	for rows.Next() {
		var version int
		var name string
		if err := rows.Scan(&version, &name); err != nil {
			_ = rows.Close()
			return 0, err
		}
		if count >= len(known) || known[count].Version != version || known[count].Name != name {
			_ = rows.Close()
			return 0, errors.New("backup database has unknown or incompatible migrations")
		}
		count++
		last = version
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return 0, err
	}
	if count == 0 {
		return 0, errors.New("backup database has no supported schema")
	}
	var schema string
	if err := conn.QueryRowContext(ctx, "SELECT substr(value,1,64) FROM metadata WHERE key='schema_version'").Scan(&schema); err != nil {
		return 0, err
	}
	if schema != strconv.Itoa(last) {
		return 0, errors.New("backup database schema metadata disagrees with migrations")
	}
	// Current snapshots must contain their startup-critical owner tables. Older
	// recognized prefixes are inspected without applying migrations; the restore
	// compatibility/maintenance layer decides whether an upgrade is acceptable.
	if count == len(known) {
		for _, table := range required {
			var found string
			if err := conn.QueryRowContext(ctx, "SELECT name FROM sqlite_schema WHERE type='table' AND name=?", table).Scan(&found); err != nil {
				return 0, errors.New("backup database is missing a required owner table")
			}
		}
	}
	return last, nil
}
