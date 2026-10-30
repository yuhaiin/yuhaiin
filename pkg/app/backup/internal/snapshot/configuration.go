package snapshot

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"

	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

// These tables are owned runtime state or private deployment identity, not
// configuration exports. New tables must be classified before uploading.
var excludedTables = []string{
	"backup_recovery_history", "backup_recovery_imports", "certificate_acme_accounts",
	"certificate_dns_cleanup", "certificate_dns_providers", "certificate_references",
	"connection_history", "connection_sessions", "failed_connection_history",
	"failure_dimension_daily", "failure_dimension_hourly", "fakeip_cursors", "fakeip_entries", "fakeip_pool_counts",
	"gateway_ca", "gateway_statistics", "inbound_statistics", "managed_certificate_material", "managed_certificates",
	"node_runtime_stats", "node_speed_budget", "statistics_kv", "telemetry_dimension_values",
	"traffic_dimension_daily", "traffic_dimension_hourly", "traffic_hourly",
	"user_usage_activity", "user_usage_audit", "user_usage_buckets", "user_usage_flush", "user_usage_totals", "user_usage_users",
}

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

	// A denylist silently exports secrets when new owners add tables. Use the
	// same configuration-only allowlist as the existing import/export format;
	// retain migration metadata so older S3 objects remain SQLite snapshots.
	rows, err := tx.QueryContext(ctx, `SELECT name, type FROM pragma_table_list WHERE schema='main' AND type IN ('table','virtual','shadow') AND substr(name,1,7) != 'sqlite_'`)
	if err != nil {
		return fmt.Errorf("list backup snapshot tables: %w", err)
	}
	type tableInfo struct{ name, kind string }
	var tables []tableInfo
	for rows.Next() {
		var table tableInfo
		if err := rows.Scan(&table.name, &table.kind); err != nil {
			_ = rows.Close()
			return err
		}
		tables = append(tables, table)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `PRAGMA defer_foreign_keys=ON`); err != nil {
		return err
	}
	allowed := storagesqlite.ConfigurationBackupTables()
	for _, table := range tables {
		// Keep the retired nodes index structurally valid after clearing its
		// owner rows. Deleting FTS shadow tables directly corrupts SQLite.
		if table.kind == "virtual" || table.kind == "shadow" {
			if table.name == "nodes_fts" || table.kind == "shadow" && strings.HasPrefix(table.name, "nodes_fts_") {
				continue
			}
			return fmt.Errorf("unsupported virtual table %s in configuration snapshot", table.name)
		}
		if table.name == "migrate" || slices.Contains(allowed, table.name) {
			continue
		}
		if !slices.Contains(excludedTables, table.name) {
			return fmt.Errorf("unclassified backup table %q: classify it as configuration or runtime data", table.name)
		}
		quoted := `"` + strings.ReplaceAll(table.name, `"`, `""`) + `"`
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+quoted); err != nil {
			return fmt.Errorf("clear non-configuration table %s from backup snapshot: %w", table.name, err)
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM metadata WHERE key NOT IN ('schema_version', 'selected_tcp_node_v2', 'selected_udp_node_v2')`); err != nil {
		return fmt.Errorf("clear non-configuration metadata from backup snapshot: %w", err)
	}
	if err := storagesqlite.SanitizeConfigurationSnapshotContent(ctx, tx); err != nil {
		return fmt.Errorf("sanitize configuration in backup snapshot: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO nodes_fts(nodes_fts) VALUES('rebuild')`); err != nil {
		return fmt.Errorf("rebuild configuration search index: %w", err)
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
		normalized, err := storagesqlite.ConfigurationBackupSettings(data)
		if err != nil {
			return fmt.Errorf("sanitize backup settings in backup snapshot: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE backup_settings
			SET updated_at = 0, data_json = ?
			WHERE id = 1
		`, normalized); err != nil {
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
