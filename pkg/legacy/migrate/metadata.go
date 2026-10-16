package migrate

import (
	"context"
	"database/sql"
	"errors"
)

// Metadata helpers shared by SQLite legacy-format migrations.
func legacyMetadata(ctx context.Context, db *sql.DB, key string) (string, error) {
	var value string
	err := db.QueryRowContext(ctx, `SELECT value FROM metadata WHERE key = ?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return value, err
}

func setLegacyMetadataTx(ctx context.Context, tx *sql.Tx, values map[string]string) error {
	for key, value := range values {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO metadata(key, value)
			VALUES (?, ?)
			ON CONFLICT(key) DO UPDATE SET value = excluded.value
		`, key, value); err != nil {
			return err
		}
	}
	return nil
}
