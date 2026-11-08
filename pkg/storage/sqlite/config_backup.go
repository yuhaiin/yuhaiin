package sqlite

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	contractbackup "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite/configbackup"
)

const MaxConfigBackupBytes = 32 << 20

// ConfigBackup is a versioned configuration snapshot. Identifiers and column
// names are checked against the local schema before any data is changed. A
// device backup also carries deviceBackupTables (credentials, certificates and
// traffic totals); fake IPs, sessions and migration markers stay on the device.
type ConfigBackup struct {
	Format              string                       `json:"format"`
	Version             int                          `json:"version"`
	CreatedAt           time.Time                    `json:"createdAt"`
	Tables              map[string]ConfigBackupTable `json:"tables"`
	missingLegacyTables map[string]bool
}

type ConfigBackupTable struct {
	Columns              []string           `json:"columns"`
	Rows                 [][]jsontext.Value `json:"rows"`
	requiresGatewayGuard bool
}

// Parent tables precede children. Restore deletes them in reverse order.
var configBackupTables = []string{
	"settings_kv", "settings_json", "android_extra_preferences",
	"dns_settings", "dns_hosts", "dns_fakedns_lists", "dns_resolvers", "resolvers_v2",
	"inbound_settings", "inbounds", "inbounds_v2", "nodes", "nodes_v2", "node_tags", "outbound_selectors",
	"subscriptions", "publishes", "route_settings", "route_rules", "route_rules_v2",
	"route_lists", "route_list_refresh", "route_lists_v2", "route_registries", "backup_settings", "metadata",
	"gateway_configuration", "gateway_references", "node_monitoring_settings",
	"user_usage_settings", "inbound_traffic_control", "route_configuration_state",
}

// Retain these schemas for historical imports, not their inactive data in new
// plaintext exports. Current owners use typed v2 resources and Set nodes. A
// guessed credential-field list cannot safely sanitize opaque legacy records.
var retiredConfigBackupTables = []string{"settings_json", "node_tags", "nodes", "inbounds"}

// deviceBackupTables travel only in a device backup (ExportDeviceBackup):
// credentials referenced by nodes, managed certificates and their keys, the
// gateway CA, and the traffic totals and hourly history. A backup without them
// leaves the current rows untouched on restore. Parents precede children.
var deviceBackupTables = []string{
	"upstream_credentials",
	"managed_certificates", "managed_certificate_material", "certificate_dns_providers",
	"certificate_acme_accounts", "certificate_references", "gateway_ca",
	"statistics_kv", "traffic_hourly",
}

// backupTables returns every table a backup may contain, in restore order.
func backupTables() []string { return slices.Concat(configBackupTables, deviceBackupTables) }

// ConfigurationBackupTables returns the tables used by configuration export.
// Callers sanitizing a private SQLite snapshot must separately filter metadata.
func ConfigurationBackupTables() []string { return slices.Clone(configBackupTables) }

// SanitizeConfigurationSnapshotContent applies the configuration export
// projections to a private snapshot without accumulating documents in memory.
func SanitizeConfigurationSnapshotContent(ctx context.Context, tx *sql.Tx) error {
	var routeState int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM route_configuration_state WHERE id=1`).Scan(&routeState); err != nil {
		return fmt.Errorf("read route activation state: %w", err)
	}
	if routeState != 1 {
		return errors.New("configuration backup requires route activation state")
	}
	for _, table := range retiredConfigBackupTables {
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+table); err != nil {
			return err
		}
	}
	// Subscription URLs can carry bearer credentials in an arbitrary path.
	// They must be re-entered explicitly rather than guessed from URL syntax.
	if _, err := tx.ExecContext(ctx, `DELETE FROM subscriptions`); err != nil {
		return err
	}
	for _, key := range []string{"refresh_config", "maxminddb_geoip"} {
		var data string
		err := tx.QueryRowContext(ctx, `SELECT value_json FROM settings_kv WHERE section='route_extra' AND key=?`, key).Scan(&data)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		cleaned, changed, err := configbackup.RouteRefreshErrors(data, "error")
		if err != nil {
			return err
		}
		if changed {
			if _, err := tx.ExecContext(ctx, `UPDATE settings_kv SET value_json=? WHERE section='route_extra' AND key=?`, cleaned, key); err != nil {
				return err
			}
		}
	}
	for _, spec := range []struct{ table, key, disable string }{
		{"nodes_v2", "id", "enabled=0"},
		{"inbounds_v2", "id", "enabled=0"},
	} {
		if err := sanitizeSnapshotDocuments(ctx, tx, spec.table, spec.key, spec.disable); err != nil {
			return err
		}
	}
	for _, spec := range []struct{ table, key string }{{"publishes", "name"}, {"gateway_configuration", "id"}, {"route_lists_v2", "id"}} {
		if err := sanitizeSnapshotDocuments(ctx, tx, spec.table, spec.key, ""); err != nil {
			return err
		}
	}
	return configbackup.ValidateSnapshotSourceURLs(ctx, tx)
}

func sanitizeSnapshotDocuments(ctx context.Context, tx *sql.Tx, table, key, disable string) error {
	last, first := "", true
	for {
		query := `SELECT ` + key + `,data_json FROM ` + table
		var args []any
		if !first {
			query += ` WHERE ` + key + `>?`
			args = []any{last}
		}
		rows, err := tx.QueryContext(ctx, query+` ORDER BY `+key+` LIMIT 128`, args...)
		if err != nil {
			return err
		}
		type replacement struct{ id, data string }
		var replacements []replacement
		count, bytes := 0, 0
		for rows.Next() {
			var id, raw string
			if err := rows.Scan(&id, &raw); err != nil {
				_ = rows.Close()
				return err
			}
			var redacted string
			var changed bool
			switch table {
			case "route_lists_v2":
				redacted, changed, err = configbackup.RouteRefreshErrors(raw, "errorMsgs")
			case "publishes":
				redacted, changed, err = configbackup.Publish(raw)
			case "gateway_configuration":
				redacted, changed, _, err = configbackup.Gateway(raw)
			default:
				redacted, changed, err = sanitizeEndpointDocument(table, raw)
			}
			if err != nil {
				_ = rows.Close()
				return err
			}
			count++
			last, first = id, false
			if changed {
				replacements = append(replacements, replacement{id, redacted})
				bytes += len(id) + len(redacted)
			}
			// One exceptionally large document can exceed this cap, but the
			// pending set never retains more than one beyond the 1 MiB budget.
			if bytes >= 1<<20 {
				break
			}
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return err
		}
		for _, item := range replacements {
			prefix := ""
			if disable != "" {
				prefix = disable + ","
			}
			if _, err := tx.ExecContext(ctx, `UPDATE `+table+` SET `+prefix+`data_json=? WHERE `+key+`=?`, item.data, item.id); err != nil {
				return err
			}
		}
		if count == 0 {
			return nil
		}
	}
}

func sanitizeEndpointDocument(table, raw string) (string, bool, error) {
	switch table {
	case "nodes_v2":
		return configbackup.Node(raw)
	case "inbounds_v2":
		return configbackup.Inbound(raw)
	default:
		return configbackup.Endpoint(raw)
	}
}

func backupTextValue(value any) (string, bool) {
	switch text := value.(type) {
	case string:
		return text, true
	case []byte:
		return string(text), true
	default:
		return "", false
	}
}

// ConfigurationBackupSettings removes transport credentials and destructive
// automation consent while preserving the remaining configuration fields.
func ConfigurationBackupSettings(data string) (string, error) {
	var options contractbackup.Option
	if err := json.Unmarshal([]byte(data), &options); err != nil {
		return "", errors.New("invalid configuration backup settings")
	}
	options.LastBackupHash = ""
	options.S3.AccessKey, options.S3.SecretKey, options.S3.Enabled = "", "", false
	if options.Recovery != nil {
		options.Recovery.Enabled, options.Recovery.AllowMaintenance = false, false
		if options.Recovery.LocalPoints != nil {
			options.Recovery.LocalPoints.Enabled = false
		}
	}
	encoded, err := json.Marshal(options)
	if err != nil {
		return "", errors.New("cannot encode configuration backup settings")
	}
	return string(encoded), nil
}

func configBackupFilter(table string) string {
	if table == "metadata" {
		return " WHERE key IN ('selected_tcp_node_v2', 'selected_udp_node_v2')"
	}
	return ""
}

// exportMode selects how much of the configuration an export carries.
type exportMode int

const (
	// exportShareable removes credentials and disables changed endpoints, so
	// the file can be handed to someone else.
	exportShareable exportMode = iota
	// exportLocalRestore feeds the private offline importer.
	exportLocalRestore
	// exportDevice is a complete backup for the same user: credentials,
	// enabled state, publishes, gateway policy and subscriptions are kept so a
	// restore works without re-entering anything.
	exportDevice
)

// ExportConfig is a shareable export without credentials.
func ExportConfig(ctx context.Context, db *sql.DB) ([]byte, error) {
	return exportConfig(ctx, db, exportShareable)
}

// ExportDeviceBackup is a complete, unencrypted backup that restores every
// node and inbound as it was, including passwords and keys. Only hand it to
// the device owner.
func ExportDeviceBackup(ctx context.Context, db *sql.DB) ([]byte, error) {
	return exportConfig(ctx, db, exportDevice)
}

// ExportConfigForLocalRestore projects a historical SQLite object for the
// private, offline configuration importer. It preserves existing source URLs;
// never use it for an external plaintext export or upload.
func ExportConfigForLocalRestore(ctx context.Context, db *sql.DB) ([]byte, error) {
	return exportConfig(ctx, db, exportLocalRestore)
}

func exportConfig(ctx context.Context, db *sql.DB, mode exportMode) ([]byte, error) {
	// A deferred SQLite transaction gives every export query one snapshot. The
	// engine does not offer a per-transaction read-only setting.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	backup := ConfigBackup{Format: "yuhaiin-config", Version: 1, CreatedAt: time.Now().UTC(), Tables: make(map[string]ConfigBackupTable)}
	tables := configBackupTables
	if mode == exportDevice {
		tables = backupTables()
	}
	for _, table := range tables {
		if slices.Contains(deviceBackupTables, table) {
			// Optional features create these tables lazily (Android has no
			// management store, for example).
			exists, err := tableExists(ctx, tx, table)
			if err != nil {
				return nil, err
			}
			if !exists {
				continue
			}
		}
		data, err := readConfigTable(ctx, tx, table, mode)
		if err != nil {
			return nil, fmt.Errorf("export %s: %w", table, err)
		}
		backup.Tables[table] = data
		if data.requiresGatewayGuard {
			backup.Version = 2
		}
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

func readConfigTable(ctx context.Context, tx *sql.Tx, table string, mode exportMode) (ConfigBackupTable, error) {
	localRestore, device := mode == exportLocalRestore, mode == exportDevice
	if table == "inbound_traffic_control" {
		var exists bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='inbound_traffic_control')`).Scan(&exists); err != nil {
			return ConfigBackupTable{}, err
		}
		if !exists {
			return ConfigBackupTable{Columns: []string{"id", "config_json"}, Rows: [][]jsontext.Value{}}, nil
		}
	}
	filter := configBackupFilter(table)
	// Restore clears subscriptions, so only a device backup may carry them;
	// their URLs can hold bearer credentials.
	if table == "subscriptions" && !device || !localRestore && slices.Contains(retiredConfigBackupTables, table) {
		filter = " WHERE 0"
	}
	rows, err := tx.QueryContext(ctx, "SELECT * FROM "+table+filter)
	if err != nil {
		return ConfigBackupTable{}, err
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return ConfigBackupTable{}, err
	}
	// Only device-only tables use the base64 cell form, so shareable exports
	// stay readable by older cores.
	blobColumns := make([]bool, len(columns))
	if slices.Contains(deviceBackupTables, table) {
		types, err := rows.ColumnTypes()
		if err != nil {
			return ConfigBackupTable{}, err
		}
		for i, column := range types {
			blobColumns[i] = strings.EqualFold(column.DatabaseTypeName(), "BLOB")
		}
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
		if table == "route_list_refresh" {
			index := slices.Index(columns, "last_error")
			if index < 0 {
				return out, errors.New("invalid route refresh schema")
			}
			values[index] = ""
		}
		if table == "settings_kv" {
			section, key, data := slices.Index(columns, "section"), slices.Index(columns, "key"), slices.Index(columns, "value_json")
			if section < 0 || key < 0 || data < 0 {
				return out, errors.New("invalid settings schema")
			}
			sectionName, sectionOK := backupTextValue(values[section])
			keyName, keyOK := backupTextValue(values[key])
			if !sectionOK || !keyOK {
				return out, errors.New("invalid settings key")
			}
			if sectionName == "route_extra" && (keyName == "refresh_config" || keyName == "maxminddb_geoip") {
				raw, ok := backupTextValue(values[data])
				if !ok {
					return out, errors.New("invalid route refresh settings")
				}
				values[data], _, err = configbackup.RouteRefreshErrors(raw, "error")
				if err != nil {
					return out, err
				}
			}
		}
		if table == "route_lists_v2" {
			index := slices.Index(columns, "data_json")
			if index < 0 {
				return out, errors.New("invalid route list schema")
			}
			raw, ok := backupTextValue(values[index])
			if !ok {
				return out, errors.New("invalid route list configuration")
			}
			values[index], _, err = configbackup.RouteRefreshErrors(raw, "errorMsgs")
			if err != nil {
				return out, err
			}
		}
		if !device && slices.Contains([]string{"nodes", "nodes_v2", "inbounds", "inbounds_v2"}, table) {
			dataIndex := slices.Index(columns, "data_json")
			if dataIndex < 0 {
				return out, errors.New("invalid endpoint configuration schema")
			}
			if table == "nodes" {
				searchIndex := slices.Index(columns, "search_text")
				if searchIndex < 0 {
					return out, errors.New("invalid legacy node configuration schema")
				}
				values[searchIndex] = ""
			}
			raw, ok := values[dataIndex].(string)
			if data, isBytes := values[dataIndex].([]byte); isBytes {
				raw, ok = string(data), true
			}
			if !ok {
				return out, errors.New("invalid endpoint configuration in export")
			}
			redacted, changed, err := sanitizeEndpointDocument(table, raw)
			if err != nil {
				return out, err
			}
			if changed {
				values[dataIndex] = redacted
				fields := []string{"enabled"}
				if table == "nodes" {
					fields = []string{"selected_tcp", "selected_udp"}
				}
				for _, field := range fields {
					index := slices.Index(columns, field)
					if index < 0 {
						return out, errors.New("invalid endpoint configuration schema")
					}
					values[index] = int64(0)
				}
			}
		}
		if !device && (table == "publishes" || table == "gateway_configuration") {
			index := slices.Index(columns, "data_json")
			if index < 0 {
				return out, errors.New("invalid configuration document schema")
			}
			raw, ok := values[index].(string)
			if data, isBytes := values[index].([]byte); isBytes {
				raw, ok = string(data), true
			}
			if !ok {
				return out, errors.New("invalid configuration document in export")
			}
			if table == "publishes" {
				values[index], _, err = configbackup.Publish(raw)
			} else {
				var guarded bool
				values[index], _, guarded, err = configbackup.Gateway(raw)
				out.requiresGatewayGuard = out.requiresGatewayGuard || guarded
			}
			if err != nil {
				return out, err
			}
		}
		if mode == exportShareable {
			if err := configbackup.ValidateSourceURLRow(table, columns, values); err != nil {
				return out, err
			}
		}
		if table == "managed_certificates" {
			// Renewal leases belong to the exporting process.
			for column, reset := range map[string]any{"lease_owner": "", "lease_until": int64(0)} {
				if index := slices.Index(columns, column); index >= 0 {
					values[index] = reset
				}
			}
		}
		row := make([]jsontext.Value, len(columns))
		for i, value := range values {
			if b, ok := value.([]byte); ok {
				if blobColumns[i] {
					// Keys and tokens keep their exact bytes and BLOB storage.
					row[i], err = json.Marshal(map[string]string{"base64": base64.StdEncoding.EncodeToString(b)})
					if err != nil {
						return out, err
					}
					continue
				}
				value = string(b)
			}
			if !device && table == "backup_settings" && columns[i] == "data_json" {
				raw, ok := value.(string)
				if !ok {
					return out, errors.New("invalid configuration backup settings")
				}
				value, err = ConfigurationBackupSettings(raw)
				if err != nil {
					return out, err
				}
			}
			encoded, err := json.Marshal(value)
			if err != nil {
				return out, err
			}
			row[i] = encoded
		}
		out.Rows = append(out.Rows, row)
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	if table == "route_configuration_state" && len(out.Rows) != 1 {
		return out, errors.New("configuration backup requires route activation state")
	}
	return out, nil
}

func decodeConfigBackup(data []byte) (ConfigBackup, error) {
	var backup ConfigBackup
	if len(data) == 0 || len(data) > MaxConfigBackupBytes {
		return backup, errors.New("configuration backup must be between 1 byte and 32 MiB")
	}
	if err := json.Unmarshal(data, &backup, json.RejectUnknownMembers(true)); err != nil {
		return backup, fmt.Errorf("invalid backup: %w", err)
	}
	if backup.Format != "yuhaiin-config" || (backup.Version != 1 && backup.Version != 2) {
		return backup, errors.New("unsupported configuration backup format or version")
	}
	backup.missingLegacyTables = make(map[string]bool)
	for name, columns := range map[string][]string{
		"node_monitoring_settings":  {"id", "data_json"},
		"user_usage_settings":       {"id", "options_json"},
		"inbound_traffic_control":   {"id", "config_json"},
		"route_configuration_state": {"id", "saved_revision", "applied_revision", "applied_rules_json", "applied_config_json"},
	} {
		if _, ok := backup.Tables[name]; !ok {
			backup.Tables[name] = ConfigBackupTable{Columns: columns, Rows: [][]jsontext.Value{}}
			backup.missingLegacyTables[name] = true
		}
	}
	for name := range backup.Tables {
		if slices.Contains(deviceBackupTables, name) {
			continue
		}
		if !slices.Contains(configBackupTables, name) {
			return backup, fmt.Errorf("unknown configuration table %s", name)
		}
	}
	if len(backup.Tables) != len(configBackupTables)+countDeviceTables(backup.Tables) {
		return backup, errors.New("incomplete configuration backup")
	}
	for _, name := range configBackupTables {
		if _, ok := backup.Tables[name]; !ok {
			return backup, fmt.Errorf("missing configuration table %s", name)
		}
	}
	// Pre-v18 exports have the same configuration format without the opt-in
	// selector policy column. Upgrade only this exact, known older shape.
	selectors := backup.Tables["outbound_selectors"]
	if slices.Equal(selectors.Columns, []string{"id", "name", "node_id", "revision"}) {
		selectors.Columns = append(selectors.Columns, "policy_json")
		for i, row := range selectors.Rows {
			if len(row) != 4 {
				return backup, errors.New("invalid legacy selector row")
			}
			selectors.Rows[i] = append(row, jsontext.Value(`"null"`))
		}
		backup.Tables["outbound_selectors"] = selectors
	}
	return backup, nil
}

// ValidateConfig performs a restore in a transaction that is always rolled back.
// This checks schema, scalar types and SQL constraints before disconnecting a VPN.
func ValidateConfig(ctx context.Context, db *sql.DB, data []byte) error {
	return restoreConfig(ctx, db, data, false)
}

func validateConfigTables(ctx context.Context, tx *sql.Tx, backup ConfigBackup) error {
	// This table is lazily created by the existing inbound store. Restore must
	// work even on an instance that has never used traffic control.
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS inbound_traffic_control (id INTEGER PRIMARY KEY CHECK(id=1), config_json TEXT NOT NULL)`); err != nil {
		return err
	}
	tables := slices.Clone(configBackupTables)
	for _, name := range deviceBackupTables {
		if _, ok := backup.Tables[name]; !ok {
			continue
		}
		exists, err := tableExists(ctx, tx, name)
		if err != nil {
			return err
		}
		if !exists {
			// The feature does not exist here; its rows cannot be used.
			delete(backup.Tables, name)
			continue
		}
		tables = append(tables, name)
	}
	for _, name := range tables {
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
		if name == "route_configuration_state" && !backup.missingLegacyTables[name] && len(table.Rows) != 1 {
			return errors.New("configuration backup requires route activation state")
		}
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

func tableExists(ctx context.Context, tx *sql.Tx, table string) (bool, error) {
	var exists bool
	err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?)`, table).Scan(&exists)
	return exists, err
}

func countDeviceTables(tables map[string]ConfigBackupTable) int {
	n := 0
	for _, name := range deviceBackupTables {
		if _, ok := tables[name]; ok {
			n++
		}
	}
	return n
}

// presentTables lists, in restore order, the tables this backup replaces.
func (b ConfigBackup) presentTables() []string {
	return slices.DeleteFunc(backupTables(), func(name string) bool {
		_, ok := b.Tables[name]
		return !ok || b.missingLegacyTables[name]
	})
}

func configCell(cell jsontext.Value) (any, error) {
	if string(cell) == "null" {
		return nil, nil
	}
	if len(cell) > 0 && cell[0] == '{' {
		var blob struct {
			Base64 string `json:"base64"`
		}
		if err := json.Unmarshal(cell, &blob, json.RejectUnknownMembers(true)); err != nil {
			return nil, errors.New("invalid binary backup cell")
		}
		return base64.StdEncoding.DecodeString(blob.Base64)
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
	present := backup.presentTables()
	if slices.Contains(present, "certificate_dns_providers") {
		// Pending TXT cleanups point at the providers being replaced.
		if _, err := tx.ExecContext(ctx, "DELETE FROM certificate_dns_cleanup"); err != nil {
			return fmt.Errorf("clear certificate_dns_cleanup: %w", err)
		}
	}
	for _, name := range slices.Backward(present) {
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+name+configBackupFilter(name)); err != nil {
			return fmt.Errorf("clear %s: %w", name, err)
		}
	}
	for _, name := range present {
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
	if backup.missingLegacyTables["route_configuration_state"] {
		result, err := tx.ExecContext(ctx, `UPDATE route_configuration_state SET applied_revision=0, applied_rules_json='[]', applied_config_json='{}' WHERE id=1`)
		if err != nil {
			return fmt.Errorf("reset legacy route activation: %w", err)
		}
		if n, err := result.RowsAffected(); err != nil || n != 1 {
			return errors.New("target is missing route activation state")
		}
	}
	if !commit {
		return nil
	}
	return tx.Commit()
}
