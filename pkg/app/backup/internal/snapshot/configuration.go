package snapshot

import (
	"context"
	"database/sql"
	"encoding/json/v2"
	"errors"
	"fmt"

	contractbackup "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func SanitizeConfiguration(ctx context.Context, path string) error {
	store, err := storagesqlite.Open(ctx, path)
	if err != nil {
		return fmt.Errorf("open sqlite backup snapshot for sanitizing failed: %w", err)
	}
	defer func() { _ = store.Close() }()

	db := store.DB()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin sqlite backup snapshot sanitizing failed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, table := range backupRuntimeTables {
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+table); err != nil {
			return fmt.Errorf("clear runtime table %s from backup snapshot failed: %w", table, err)
		}
	}

	// Refresh timestamps and errors are runtime bookkeeping, not configuration.
	if _, err := tx.ExecContext(ctx, `
		UPDATE route_list_refresh
		SET last_refresh_time = 0, last_error = ''
	`); err != nil {
		return fmt.Errorf("normalize route list refresh state in backup snapshot failed: %w", err)
	}

	// LastBackupHash and updated_at are written after every successful upload.
	// Normalize both fields so saving the hash does not invalidate the next
	// snapshot by itself.
	var data string
	err = tx.QueryRowContext(ctx, `
		SELECT data_json
		FROM backup_settings
		WHERE id = 1
	`).Scan(&data)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read backup settings from backup snapshot failed: %w", err)
	}
	if err == nil {
		var opt contractbackup.Option
		if err := json.Unmarshal([]byte(data), &opt); err != nil {
			return fmt.Errorf("decode backup settings from backup snapshot failed: %w", err)
		}
		opt.LastBackupHash = ""
		normalized, err := json.Marshal(opt)
		if err != nil {
			return fmt.Errorf("encode normalized backup settings failed: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE backup_settings
			SET updated_at = 0, data_json = ?
			WHERE id = 1
		`, string(normalized)); err != nil {
			return fmt.Errorf("normalize backup settings in backup snapshot failed: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit sqlite backup snapshot sanitizing failed: %w", err)
	}

	if _, err := db.ExecContext(ctx, "VACUUM"); err != nil {
		return fmt.Errorf("compact sanitized sqlite backup snapshot failed: %w", err)
	}

	return nil
}
