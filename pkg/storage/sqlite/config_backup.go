package sqlite

import (
	"context"
	"database/sql"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

const MaxConfigBackupBytes = 32 << 20

// ConfigBackup is a versioned, configuration-only snapshot. Identifiers and
// column names are checked against the local schema before any data is changed.
// Runtime counters, history, fake IPs and migration markers stay on the device.
type ConfigBackup struct {
	Format    string                       `json:"format"`
	Version   int                          `json:"version"`
	CreatedAt time.Time                    `json:"createdAt"`
	Tables    map[string]ConfigBackupTable `json:"tables"`
}

type ConfigBackupTable struct {
	Columns []string           `json:"columns"`
	Rows    [][]jsontext.Value `json:"rows"`
}

// Parent tables precede children. Restore deletes them in reverse order.
var configBackupTables = []string{
	"settings_kv", "settings_json", "android_extra_preferences",
	"dns_settings", "dns_hosts", "dns_fakedns_lists", "dns_resolvers", "resolvers_v2",
	"inbound_settings", "inbounds", "inbounds_v2", "nodes", "nodes_v2", "node_tags", "node_tags_v2",
	"subscriptions", "publishes", "route_settings", "route_rules", "route_rules_v2",
	"route_lists", "route_list_refresh", "route_lists_v2", "route_registries", "backup_settings", "metadata",
}

func configBackupFilter(table string) string {
	if table == "metadata" {
		return " WHERE key IN ('selected_tcp_node_v2', 'selected_udp_node_v2')"
	}
	return ""
}

func ExportConfig(ctx context.Context, db *sql.DB) ([]byte, error) {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	backup := ConfigBackup{Format: "yuhaiin-config", Version: 1, CreatedAt: time.Now().UTC(), Tables: make(map[string]ConfigBackupTable)}
	for _, table := range configBackupTables {
		data, err := readConfigTable(ctx, tx, table)
		if err != nil {
			return nil, fmt.Errorf("export %s: %w", table, err)
		}
		backup.Tables[table] = data
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(backup)
	if len(data) > MaxConfigBackupBytes {
		return nil, errors.New("configuration backup exceeds 32 MiB")
	}
	return data, err
}

func readConfigTable(ctx context.Context, tx *sql.Tx, table string) (ConfigBackupTable, error) {
	rows, err := tx.QueryContext(ctx, "SELECT * FROM "+table+configBackupFilter(table))
	if err != nil {
		return ConfigBackupTable{}, err
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return ConfigBackupTable{}, err
	}
	out := ConfigBackupTable{Columns: columns, Rows: make([][]jsontext.Value, 0)}
	for rows.Next() {
		values := make([]any, len(columns))
		pointers := make([]any, len(columns))
		for i := range values {
			pointers[i] = &values[i]
		}
		if err := rows.Scan(pointers...); err != nil {
			return out, err
		}
		row := make([]jsontext.Value, len(columns))
		for i, value := range values {
			if b, ok := value.([]byte); ok {
				value = string(b)
			}
			encoded, err := json.Marshal(value)
			if err != nil {
				return out, err
			}
			row[i] = encoded
		}
		out.Rows = append(out.Rows, row)
	}
	return out, rows.Err()
}

func decodeConfigBackup(data []byte) (ConfigBackup, error) {
	var backup ConfigBackup
	if len(data) == 0 || len(data) > MaxConfigBackupBytes {
		return backup, errors.New("configuration backup must be between 1 byte and 32 MiB")
	}
	if err := json.Unmarshal(data, &backup, json.RejectUnknownMembers(true)); err != nil {
		return backup, fmt.Errorf("invalid backup: %w", err)
	}
	if backup.Format != "yuhaiin-config" || backup.Version != 1 {
		return backup, errors.New("unsupported configuration backup format or version")
	}
	if len(backup.Tables) != len(configBackupTables) {
		return backup, errors.New("incomplete configuration backup")
	}
	for _, name := range configBackupTables {
		if _, ok := backup.Tables[name]; !ok {
			return backup, fmt.Errorf("missing configuration table %s", name)
		}
	}
	return backup, nil
}

// ValidateConfig performs a restore in a transaction that is always rolled back.
// This checks schema, scalar types and SQL constraints before disconnecting a VPN.
func ValidateConfig(ctx context.Context, db *sql.DB, data []byte) error {
	return restoreConfig(ctx, db, data, false)
}

func validateConfigTables(ctx context.Context, tx *sql.Tx, backup ConfigBackup) error {
	for _, name := range configBackupTables {
		rows, err := tx.QueryContext(ctx, "SELECT * FROM "+name+" LIMIT 0")
		if err != nil {
			return err
		}
		columns, err := rows.Columns()
		_ = rows.Close()
		if err != nil {
			return err
		}
		table := backup.Tables[name]
		if !slices.Equal(columns, table.Columns) {
			return fmt.Errorf("incompatible backup schema for %s", name)
		}
		for _, row := range table.Rows {
			if len(row) != len(columns) {
				return fmt.Errorf("invalid row in %s", name)
			}
			for _, cell := range row {
				if _, err := configCell(cell); err != nil {
					return err
				}
			}
			if name == "metadata" {
				key, err := configCell(row[0])
				if err != nil || (key != "selected_tcp_node_v2" && key != "selected_udp_node_v2") {
					return errors.New("backup contains non-configuration metadata")
				}
			}
		}
	}
	return nil
}

func configCell(cell jsontext.Value) (any, error) {
	if string(cell) == "null" {
		return nil, nil
	}
	if len(cell) > 0 && cell[0] == '"' {
		var value string
		err := json.Unmarshal(cell, &value)
		return value, err
	}
	value, err := strconv.ParseInt(string(cell), 10, 64)
	if err != nil {
		return nil, errors.New("backup table cells must be strings, integers or null")
	}
	return value, nil
}

// RestoreConfig changes the existing database in one transaction, so open
// preference connections in other Android processes see the restored settings.
// Callers must stop the runtime first so its in-memory configuration is reloaded.
func RestoreConfig(ctx context.Context, db *sql.DB, data []byte) error {
	return restoreConfig(ctx, db, data, true)
}

func restoreConfig(ctx context.Context, db *sql.DB, data []byte, commit bool) error {
	backup, err := decodeConfigBackup(data)
	if err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := validateConfigTables(ctx, tx, backup); err != nil {
		return err
	}
	for _, name := range slices.Backward(configBackupTables) {
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+name+configBackupFilter(name)); err != nil {
			return fmt.Errorf("clear %s: %w", name, err)
		}
	}
	for _, name := range configBackupTables {
		table := backup.Tables[name]
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(table.Columns)), ",")
		// Columns came from the local schema, never directly from an untrusted file.
		statement := "INSERT INTO " + name + " (" + strings.Join(table.Columns, ",") + ") VALUES (" + placeholders + ")"
		for _, row := range table.Rows {
			values := make([]any, len(row))
			for i, cell := range row {
				values[i], err = configCell(cell)
				if err != nil {
					return err
				}
			}
			if _, err := tx.ExecContext(ctx, statement, values...); err != nil {
				return fmt.Errorf("restore %s: %w", name, err)
			}
		}
	}
	if !commit {
		return nil
	}
	return tx.Commit()
}
