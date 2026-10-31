package snapshot

import (
	"context"
	"database/sql"
	"net/url"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func PruneRecovery(ctx context.Context, path string, includeHistory bool) error {
	// Only the staged snapshot is changed. Account/credential state, traffic
	// quota totals, active measurement reservations and protocol identity remain.
	fileURL := &url.URL{Scheme: "file", Path: filepath.ToSlash(path), RawQuery: "mode=rw"}
	if filepath.VolumeName(path) != "" && !strings.HasPrefix(fileURL.Path, "/") {
		fileURL.Path = "/" + fileURL.Path
	}
	uri := fileURL.String()
	db, err := sql.Open(sqlite.DriverName(), uri)
	if err != nil {
		return err
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, "PRAGMA secure_delete=ON"); err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	changed := false
	for _, table := range append(append([]string(nil), backupRuntimeTables...), "user_usage_audit") {
		// A staged Web import is temporary control work, never restorable
		// history: its private files are intentionally absent from inventory.
		if includeHistory && table != "backup_recovery_imports" {
			continue
		}
		if slices.Contains([]string{"statistics_kv", "fakeip_entries", "fakeip_cursors"}, table) {
			continue
		}
		var present int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name=?", table).Scan(&present); err != nil {
			return err
		}
		if present == 0 {
			continue
		}
		result, err := tx.ExecContext(ctx, "DELETE FROM "+table)
		if err != nil {
			return err
		}
		count, err := result.RowsAffected()
		if err != nil {
			return err
		}
		changed = changed || count > 0
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if includeHistory || !changed {
		return nil
	}
	_, err = db.ExecContext(ctx, "VACUUM")
	return err
}
