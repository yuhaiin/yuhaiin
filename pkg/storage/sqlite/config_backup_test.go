package sqlite

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"path/filepath"
	"testing"
)

func TestConfigBackupRoundTripAndAtomicFailure(t *testing.T) {
	ctx := t.Context()
	source, err := Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	for _, statement := range []string{
		`INSERT INTO android_extra_preferences VALUES ('route_content_custom', '"0.0.0.0/0"', 9223372036854775806)`,
		`INSERT INTO metadata VALUES ('selected_tcp_node_v2', 'test-node')`,
		`INSERT INTO metadata VALUES ('source_runtime_marker', 'do-not-export')`,
		`INSERT INTO nodes_v2 VALUES ('test-node', 'Backup node', 'test', 'manual', 1, '["direct"]', 42, '{"id":"test-node","name":"Backup node","enabled":true,"chain":[{"type":"direct","direct":{}}]}')`,
		`INSERT INTO statistics_kv VALUES ('total_download', 1000, 1)`,
	} {
		if _, err := source.DB().ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	data, err := ExportConfig(ctx, source.DB())
	if err != nil {
		t.Fatal(err)
	}
	target, err := Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	if _, err := target.DB().ExecContext(ctx, `INSERT INTO metadata VALUES ('target_marker', 'keep')`); err != nil {
		t.Fatal(err)
	}
	if _, err := target.DB().ExecContext(ctx, `INSERT INTO statistics_kv VALUES ('total_download', 700, 1)`); err != nil {
		t.Fatal(err)
	}
	if err := ValidateConfig(ctx, target.DB(), data); err != nil {
		t.Fatal(err)
	}
	if err := RestoreConfig(ctx, target.DB(), data); err != nil {
		t.Fatal(err)
	}
	var name string
	if err := target.DB().QueryRowContext(ctx, `SELECT name FROM nodes_v2`).Scan(&name); err != nil || name != "Backup node" {
		t.Fatalf("restored node: %s, %v", name, err)
	}
	var timestamp int64
	if err := target.DB().QueryRowContext(ctx, `SELECT updated_at FROM android_extra_preferences`).Scan(&timestamp); err != nil || timestamp != 9223372036854775806 {
		t.Fatalf("integer precision: %d, %v", timestamp, err)
	}
	var total int
	if err := target.DB().QueryRowContext(ctx, `SELECT value_int FROM statistics_kv`).Scan(&total); err != nil || total != 700 {
		t.Fatalf("runtime totals were overwritten: %d, %v", total, err)
	}
	var marker string
	if err := target.DB().QueryRowContext(ctx, `SELECT value FROM metadata WHERE key='target_marker'`).Scan(&marker); err != nil || marker != "keep" {
		t.Fatal("local marker changed", err)
	}
	var backup ConfigBackup
	if err := json.Unmarshal(data, &backup); err != nil {
		t.Fatal(err)
	}
	bad := backup.Tables["nodes_v2"]
	bad.Rows[0][7] = jsontext.Value(`"not valid JSON"`)
	backup.Tables["nodes_v2"] = bad
	broken, err := json.Marshal(backup)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateConfig(ctx, target.DB(), broken); err == nil {
		t.Fatal("invalid backup passed preview validation")
	}
	if err := RestoreConfig(ctx, target.DB(), broken); err == nil {
		t.Fatal("expected SQLite constraint failure")
	}
	if err := target.DB().QueryRowContext(ctx, `SELECT name FROM nodes_v2`).Scan(&name); err != nil || name != "Backup node" {
		t.Fatal("failed restore did not roll back", err)
	}
	if err := target.DB().QueryRowContext(ctx, `SELECT updated_at FROM android_extra_preferences`).Scan(&timestamp); err != nil || timestamp != 9223372036854775806 {
		t.Fatal("earlier tables were not rolled back", err)
	}
}

func TestConfigBackupRejectsIncompleteOrUnknownFormat(t *testing.T) {
	ctx := t.Context()
	store, err := Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	data, err := ExportConfig(ctx, store.DB())
	if err != nil {
		t.Fatal(err)
	}
	var backup ConfigBackup
	if err := json.Unmarshal(data, &backup); err != nil {
		t.Fatal(err)
	}
	backup.Version = 2
	future, err := json.Marshal(backup)
	if err != nil {
		t.Fatal(err)
	}
	if err := RestoreConfig(ctx, store.DB(), future); err == nil {
		t.Fatal("accepted future version")
	}
	backup.Version = 1
	delete(backup.Tables, "nodes_v2")
	partial, err := json.Marshal(backup)
	if err != nil {
		t.Fatal(err)
	}
	if err := RestoreConfig(ctx, store.DB(), partial); err == nil {
		t.Fatal("accepted incomplete backup")
	}
	backup.Tables["nodes_v2"] = ConfigBackupTable{Columns: []string{"id); DROP TABLE nodes_v2; --"}}
	invalid, err := json.Marshal(backup)
	if err != nil {
		t.Fatal(err)
	}
	if err := RestoreConfig(ctx, store.DB(), invalid); err == nil {
		t.Fatal("accepted untrusted columns")
	}
}
