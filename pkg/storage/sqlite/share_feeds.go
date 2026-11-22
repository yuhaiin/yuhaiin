package sqlite

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite/configbackup"
)

// shareFeedsMigration replaces publishes with share feeds. A share feed is
// identified by an ID so it can be renamed, and served by a random token.
// Fetch statistics are runtime data kept apart from the configuration row.
var shareFeedsMigration = Migration{Version: 28, Name: "share_feeds", Transform: migrateShareFeeds}

func migrateShareFeeds(ctx context.Context, tx *sql.Tx) error {
	for _, statement := range []string{
		`CREATE TABLE share_feeds (
			id          TEXT PRIMARY KEY,
			updated_at  INTEGER NOT NULL,
			data_json   TEXT NOT NULL CHECK (json_valid(data_json))
		)`,
		`CREATE TABLE share_feed_access (
			id            TEXT PRIMARY KEY,
			last_access   INTEGER NOT NULL DEFAULT 0,
			access_count  INTEGER NOT NULL DEFAULT 0
		)`,
	} {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	type row struct {
		name, data string
		updatedAt  int64
	}
	rows, err := tx.QueryContext(ctx, `SELECT name, updated_at, data_json FROM publishes ORDER BY name`)
	if err != nil {
		return fmt.Errorf("read publishes: %w", err)
	}
	var legacy []row
	for rows.Next() {
		var item row
		if err := rows.Scan(&item.name, &item.updatedAt, &item.data); err != nil {
			_ = rows.Close()
			return err
		}
		legacy = append(legacy, item)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, item := range legacy {
		id, document, err := configbackup.LegacyPublishShareFeed(item.name, item.data, item.updatedAt)
		if err != nil {
			log.Warn("drop invalid publish while migrating to share feeds", "name", item.name, "err", err)
			continue
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO share_feeds(id, updated_at, data_json) VALUES (?, ?, ?)`, id, item.updatedAt, document); err != nil {
			return fmt.Errorf("migrate publish %q: %w", item.name, err)
		}
	}
	_, err = tx.ExecContext(ctx, `DROP TABLE publishes`)
	return err
}
