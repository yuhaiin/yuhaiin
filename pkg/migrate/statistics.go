package migrate

import (
	"bytes"
	"context"
	"database/sql"
	jsontext "encoding/json/jsontext"
	json "encoding/json/v2"
	"fmt"
	"strconv"

	contractconnection "github.com/Asutorufa/yuhaiin/pkg/contract/connection"
	legacymigrate "github.com/Asutorufa/yuhaiin/pkg/legacy/migrate"
	legacyconfig "github.com/Asutorufa/yuhaiin/pkg/legacy/schema/config"
	legacystatistic "github.com/Asutorufa/yuhaiin/pkg/legacy/schema/statistic"
)

const plainStatisticJSONMigrationDoneKey = "plain_statistic_json_migration_done"

var legacyConnectionStringFields = []string{
	"id",
	"pid",
	"uid",
	"udpMigrateId",
	"udp_migrate_id",
}

var legacyStatisticConnectionFields = []string{
	"LocalAddr",
	"destionation",
	"fake_ip",
	"hash",
	"http_host",
	"match_history",
	"node_name",
	"tls_server_name",
	"type",
	"udp_migrate_id",
}

func migrateStatisticConnectionJSON(ctx context.Context, db *sql.DB) error {
	done, err := migrationMarker(ctx, db, plainStatisticJSONMigrationDoneKey)
	if err != nil {
		return err
	}
	if done == "1" {
		return nil
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin statistic json migration failed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := migrateStatisticJSONColumn(ctx, tx, "connection_sessions", "summary_json"); err != nil {
		return err
	}
	if err := migrateStatisticJSONColumn(ctx, tx, "connection_history", "last_connection_json"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO metadata(key, value)
		VALUES (?, '1')
		ON CONFLICT(key) DO UPDATE SET value = excluded.value
	`, plainStatisticJSONMigrationDoneKey); err != nil {
		return fmt.Errorf("mark statistic json migration done failed: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit statistic json migration failed: %w", err)
	}
	return nil
}

func migrateStatisticJSONColumn(ctx context.Context, tx *sql.Tx, table, column string) error {
	rows, err := tx.QueryContext(ctx, fmt.Sprintf(`SELECT rowid, %s FROM %s`, column, table))
	if err != nil {
		return fmt.Errorf("query %s.%s failed: %w", table, column, err)
	}
	defer rows.Close()

	type update struct {
		rowID int64
		data  string
	}
	var updates []update
	for rows.Next() {
		var rowID int64
		var data string
		if err := rows.Scan(&rowID, &data); err != nil {
			return fmt.Errorf("scan %s.%s failed: %w", table, column, err)
		}
		next, changed, err := migrateConnectionJSONNumbers(data)
		if err != nil {
			return fmt.Errorf("migrate %s.%s rowid=%d failed: %w", table, column, rowID, err)
		}
		if changed {
			updates = append(updates, update{rowID: rowID, data: next})
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate %s.%s failed: %w", table, column, err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close %s.%s rows failed: %w", table, column, err)
	}

	for _, update := range updates {
		if _, err := tx.ExecContext(ctx, fmt.Sprintf(`UPDATE %s SET %s = ? WHERE rowid = ?`, table, column), update.data, update.rowID); err != nil {
			return fmt.Errorf("update %s.%s rowid=%d failed: %w", table, column, update.rowID, err)
		}
	}
	return nil
}

func migrateConnectionJSONNumbers(data string) (string, bool, error) {
	var raw map[string]jsontext.Value
	if err := json.Unmarshal([]byte(data), &raw); err != nil {
		return "", false, err
	}

	if hasLegacyStatisticConnectionFields(raw) {
		return migrateLegacyStatisticConnectionJSON(data)
	}

	changed := false
	for _, field := range legacyConnectionStringFields {
		value, ok := raw[field]
		if !ok || value.Kind() != jsontext.KindNumber {
			continue
		}
		raw[field] = jsontext.Value(strconv.AppendQuote(nil, string(bytes.TrimSpace(value))))
		changed = true
	}
	if value, ok := raw["mode"]; ok && value.Kind() == jsontext.KindNumber {
		mode, err := strconv.ParseInt(string(bytes.TrimSpace(value)), 10, 32)
		if err != nil {
			return "", false, fmt.Errorf("mode: %w", err)
		}
		raw["mode"] = jsontext.Value(strconv.AppendQuote(nil, legacyconfig.Mode(mode).String()))
		changed = true
	}
	if !changed {
		return data, false, nil
	}

	out, err := json.Marshal(raw)
	if err != nil {
		return "", false, err
	}
	var conn contractconnection.Connection
	if err := json.Unmarshal(out, &conn); err != nil {
		return "", false, err
	}
	return string(out), true, nil
}

func hasLegacyStatisticConnectionFields(raw map[string]jsontext.Value) bool {
	for _, field := range legacyStatisticConnectionFields {
		if _, ok := raw[field]; ok {
			return true
		}
	}
	return false
}

func migrateLegacyStatisticConnectionJSON(data string) (string, bool, error) {
	var legacy legacystatistic.Connection
	if err := json.Unmarshal([]byte(data), &legacy); err != nil {
		return "", false, err
	}
	conn := legacymigrate.ConvertLegacyConnection(&legacy)
	out, err := json.Marshal(conn)
	if err != nil {
		return "", false, err
	}
	var validated contractconnection.Connection
	if err := json.Unmarshal(out, &validated); err != nil {
		return "", false, err
	}
	return string(out), true, nil
}
