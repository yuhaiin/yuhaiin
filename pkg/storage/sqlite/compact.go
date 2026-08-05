package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

const (
	startupVacuumMinFreeBytes = 4 << 20
	startupVacuumMinFreeRatio = 10
)

// Compact checkpoints the WAL, rewrites the database, and truncates the WAL
// again. It is intended for an explicit cleanup point such as graceful app
// shutdown.
func Compact(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return errors.New("sqlite database is nil")
	}

	if err := checkpoint(ctx, db, "before compact"); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, "VACUUM"); err != nil {
		return fmt.Errorf("vacuum sqlite database failed: %w", err)
	}
	if err := checkpoint(ctx, db, "after compact"); err != nil {
		return err
	}
	return nil
}

// CompactIfNeeded checkpoints the WAL and compacts the database only when the
// amount of reusable space is large enough to justify rewriting the file.
// The bool reports whether VACUUM was executed.
func CompactIfNeeded(ctx context.Context, db *sql.DB) (bool, error) {
	if db == nil {
		return false, errors.New("sqlite database is nil")
	}

	if err := checkpoint(ctx, db, "before conditional compact"); err != nil {
		return false, err
	}

	var pageCount, pageSize, freePages int64
	for _, item := range []struct {
		name  string
		query string
		value *int64
	}{
		{name: "page count", query: "PRAGMA page_count", value: &pageCount},
		{name: "page size", query: "PRAGMA page_size", value: &pageSize},
		{name: "freelist count", query: "PRAGMA freelist_count", value: &freePages},
	} {
		if err := db.QueryRowContext(ctx, item.query).Scan(item.value); err != nil {
			return false, fmt.Errorf("read sqlite %s before conditional compact failed: %w", item.name, err)
		}
	}

	freeBytes := freePages * pageSize
	freeRatio := int64(0)
	if pageCount > 0 {
		freeRatio = freePages * 100 / pageCount
	}
	if freeBytes < startupVacuumMinFreeBytes && freeRatio < startupVacuumMinFreeRatio {
		return false, nil
	}

	if _, err := db.ExecContext(ctx, "VACUUM"); err != nil {
		return false, fmt.Errorf("vacuum sqlite database conditionally failed: %w", err)
	}
	if err := checkpoint(ctx, db, "after conditional compact"); err != nil {
		return false, err
	}
	return true, nil
}

func checkpoint(ctx context.Context, db *sql.DB, phase string) error {
	if _, err := db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		return fmt.Errorf("checkpoint sqlite database %s failed: %w", phase, err)
	}
	return nil
}
