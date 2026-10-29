package backup

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	contractbackup "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	contractrecovery "github.com/Asutorufa/yuhaiin/pkg/contract/backup/recovery"
	contractsettings "github.com/Asutorufa/yuhaiin/pkg/contract/settings"
	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol"
	"github.com/Asutorufa/yuhaiin/pkg/paths"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
)

func TestConfigurationSnapshotRedactsEndpointsAcrossBoundedBatches(t *testing.T) {
	dir := t.TempDir()
	db, err := storagesqlite.Open(t.Context(), paths.PathGenerator.State(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tx, err := db.DB().BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 130 {
		id := fmt.Sprintf("node-%03d", i)
		padding := ""
		if i == 64 {
			padding = strings.Repeat("x", 1<<20)
		}
		doc := fmt.Sprintf(`{"id":%q,"name":%q,"origin":"manual","enabled":true,"chain":[{"type":"ssh","ssh":{"password":"batch-secret-marker","host_key":%q}}]}`, id, id, padding)
		if _, err := tx.ExecContext(t.Context(), `INSERT INTO nodes_v2(id,name,group_name,origin,enabled,chain_types_json,updated_at,data_json) VALUES(?,?,?,'manual',1,'["ssh"]',1,?)`, id, id, "fixture", doc); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	data, err := readBackupSnapshot(t, &Backup{dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("batch-secret-marker")) {
		t.Fatal("a batch retained a node credential")
	}
	path := filepath.Join(t.TempDir(), "snapshot.db")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	copy, err := storagesqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer copy.Close()
	var count, enabled int
	if err := copy.DB().QueryRowContext(t.Context(), `SELECT count(*),sum(enabled) FROM nodes_v2`).Scan(&count, &enabled); err != nil || count != 130 || enabled != 0 {
		t.Fatal("some endpoints were skipped or enabled", count, enabled, err)
	}
}

func TestBackupSQLiteSnapshotRestore(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sqliteStore, err := storagesqlite.Open(t.Context(), paths.PathGenerator.State(dir))
	if err != nil {
		t.Fatalf("open sqlite failed: %v", err)
	}
	settings := plainstore.NewSettingsStore(sqliteStore.DB())
	if err := backupstore.New(sqliteStore.DB()).RecordRecoveryRuntime(t.Context(), contractrecovery.Runtime{ManagementTLS: "disabled", WorkingDirectory: dir}); err != nil {
		t.Fatal(err)
	}

	if _, err := settings.Save(t.Context(), contractsettings.Settings{NetInterface: "before"}); err != nil {
		t.Fatalf("write initial sqlite config failed: %v", err)
	}
	if _, err := sqliteStore.DB().ExecContext(t.Context(), `INSERT INTO subscriptions(name,updated_at,data_json) VALUES('source',1,'{"name":"source","url":"https://example.org/source-secret","type":"reserve"}')`); err != nil {
		t.Fatal(err)
	}
	shaping := trafficcontrol.Config{Enabled: true, Global: trafficcontrol.Profile{Upload: trafficcontrol.Rate{BytesPerSecond: 2048, BurstBytes: 2048}}}
	if err := plainstore.NewInboundStore(sqliteStore.DB()).SaveTrafficControl(t.Context(), shaping); err != nil {
		t.Fatal(err)
	}
	if _, err := sqliteStore.DB().ExecContext(t.Context(), `INSERT INTO user_usage_settings(id,options_json) VALUES(1,'{"auditDays":30,"maxAuditRows":100000,"hourlyDays":30,"dailyDays":365}'); UPDATE route_configuration_state SET saved_revision=42,applied_revision=41,applied_rules_json='[]',applied_config_json='{}' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	jsonConfiguration, err := storagesqlite.ExportConfig(t.Context(), sqliteStore.DB())
	if err != nil {
		t.Fatal(err)
	}
	jsonTarget, err := storagesqlite.Open(t.Context(), filepath.Join(t.TempDir(), "json-target.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer jsonTarget.Close()
	if err := storagesqlite.RestoreConfig(t.Context(), jsonTarget.DB(), jsonConfiguration); err != nil {
		t.Fatal("configuration JSON could not be restored into a fresh database", err)
	}
	jsonShaping, err := plainstore.NewInboundStore(jsonTarget.DB()).TrafficControl(t.Context())
	if err != nil || !jsonShaping.Enabled || jsonShaping.Global.Upload.BytesPerSecond != 2048 {
		t.Fatal("configuration JSON lost traffic control", jsonShaping, err)
	}
	var jsonSavedRevision, jsonAppliedRevision int
	if err := jsonTarget.DB().QueryRowContext(t.Context(), `SELECT saved_revision,applied_revision FROM route_configuration_state WHERE id=1`).Scan(&jsonSavedRevision, &jsonAppliedRevision); err != nil || jsonSavedRevision != 42 || jsonAppliedRevision != 41 {
		t.Fatal("configuration JSON lost route activation state", jsonSavedRevision, jsonAppliedRevision, err)
	}
	var jsonUsage string
	if err := jsonTarget.DB().QueryRowContext(t.Context(), `SELECT options_json FROM user_usage_settings WHERE id=1`).Scan(&jsonUsage); err != nil || !strings.Contains(jsonUsage, `"maxAuditRows":100000`) {
		t.Fatal("configuration JSON lost usage settings", jsonUsage, err)
	}

	backup := &Backup{dir: dir}
	snapshot, err := readBackupSnapshot(t, backup)
	if err != nil {
		t.Fatalf("snapshot sqlite state failed: %v", err)
	}

	if _, err := settings.Save(t.Context(), contractsettings.Settings{NetInterface: "after"}); err != nil {
		t.Fatalf("write modified sqlite config failed: %v", err)
	}
	backupOptions := contractbackup.Option{InstanceName: "target", Interval: 30, S3: contractbackup.S3{Enabled: true, EndpointURL: "https://target.example", AccessKey: "target-access", SecretKey: "target-secret"}}
	if err := backupstore.New(sqliteStore.DB()).Save(t.Context(), backupOptions); err != nil {
		t.Fatal(err)
	}
	if _, err := sqliteStore.DB().ExecContext(t.Context(), `INSERT INTO gateway_ca VALUES(1,1,'target-cert','target-private-key')`); err != nil {
		t.Fatal(err)
	}
	if _, err := sqliteStore.DB().ExecContext(t.Context(), `INSERT INTO subscriptions(name,updated_at,data_json) VALUES('target',1,'{"name":"target","url":"https://example.org/target-secret","type":"reserve"}')`); err != nil {
		t.Fatal(err)
	}
	if err := sqliteStore.Close(); err != nil {
		t.Fatalf("close sqlite before restore failed: %v", err)
	}

	if err := backup.restoreStateDB(t.Context(), snapshot); err != nil {
		t.Fatalf("restore sqlite state failed: %v", err)
	}

	reopened, err := storagesqlite.Open(t.Context(), paths.PathGenerator.State(dir))
	if err != nil {
		t.Fatalf("reopen sqlite failed: %v", err)
	}
	defer reopened.Close()
	reopenedSettings := plainstore.NewSettingsStore(reopened.DB())
	got, err := reopenedSettings.Load(t.Context())
	if err != nil {
		t.Fatalf("view restored sqlite config failed: %v", err)
	}
	if got.NetInterface != "before" {
		t.Fatalf("expected restored net interface before, got %q", got.NetInterface)
	}
	restoredBackup, err := backupstore.New(reopened.DB()).Get(t.Context())
	if err != nil || restoredBackup != backupOptions {
		t.Fatal("legacy configuration restore did not preserve local backup settings", restoredBackup, err)
	}
	var caKey string
	if err := reopened.DB().QueryRowContext(t.Context(), `SELECT private_key_pem FROM gateway_ca`).Scan(&caKey); err != nil || caKey != "target-private-key" {
		t.Fatal("legacy configuration restore changed local CA identity", err)
	}
	var subscriptions int
	if err := reopened.DB().QueryRowContext(t.Context(), `SELECT count(*) FROM subscriptions`).Scan(&subscriptions); err != nil || subscriptions != 0 {
		t.Fatal("legacy configuration restore retained old subscriptions", subscriptions, err)
	}
	restoredShaping, err := plainstore.NewInboundStore(reopened.DB()).TrafficControl(t.Context())
	if err != nil || !restoredShaping.Enabled || restoredShaping.Global.Upload.BytesPerSecond != 2048 {
		t.Fatal("S3 configuration restore lost traffic control", restoredShaping, err)
	}
	var savedRevision, appliedRevision int
	if err := reopened.DB().QueryRowContext(t.Context(), `SELECT saved_revision,applied_revision FROM route_configuration_state WHERE id=1`).Scan(&savedRevision, &appliedRevision); err != nil || savedRevision != 42 || appliedRevision != 41 {
		t.Fatal("S3 configuration restore lost route activation state", savedRevision, appliedRevision, err)
	}
	var usageOptions string
	if err := reopened.DB().QueryRowContext(t.Context(), `SELECT options_json FROM user_usage_settings WHERE id=1`).Scan(&usageOptions); err != nil || !strings.Contains(usageOptions, `"maxAuditRows":100000`) {
		t.Fatal("S3 configuration restore lost usage settings", usageOptions, err)
	}
}

func TestLegacyBackupRestoreCannotReplaceActiveSQLiteOwner(t *testing.T) {
	directory := t.TempDir()
	db, err := storagesqlite.Open(t.Context(), paths.PathGenerator.State(directory))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	backup := &Backup{dir: directory}
	snapshot, err := readBackupSnapshot(t, backup)
	if err != nil {
		t.Fatal(err)
	}
	if err := backup.restoreStateDB(t.Context(), snapshot); err == nil {
		t.Fatal("legacy restore replaced an actively owned WAL database")
	}
	if err := db.DB().PingContext(t.Context()); err != nil {
		t.Fatal("rejected restore invalidated the current database owner", err)
	}
}

func TestBackupSQLiteSnapshotExcludesRuntimeState(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sqliteStore, err := storagesqlite.Open(t.Context(), paths.PathGenerator.State(dir))
	if err != nil {
		t.Fatalf("open sqlite failed: %v", err)
	}
	defer sqliteStore.Close()

	settings := plainstore.NewSettingsStore(sqliteStore.DB())
	if _, err := settings.Save(t.Context(), contractsettings.Settings{NetInterface: "before"}); err != nil {
		t.Fatalf("write initial sqlite config failed: %v", err)
	}
	if err := backupstore.New(sqliteStore.DB()).Save(t.Context(), contractbackup.Option{
		InstanceName:   "instance",
		Interval:       30,
		LastBackupHash: "old-hash",
	}); err != nil {
		t.Fatalf("write backup settings failed: %v", err)
	}

	db := sqliteStore.DB()
	if _, err := db.Exec(`
		INSERT INTO statistics_kv(key, value_int, updated_at) VALUES ('total_upload', 100, 1);
		INSERT INTO traffic_hourly(bucket_start_utc, upload_bytes, download_bytes, updated_at) VALUES (1, 100, 200, 1);
		INSERT INTO connection_history(protocol, addr, process_name, hit_count, last_seen_at, last_connection_json)
		VALUES (1, 'example.com:443', '', 1, 1, '{}');
		INSERT INTO fakeip_entries(family, prefix, domain, ip, created_at, last_used_at)
		VALUES (4, '198.18.0.0/15', 'example.com', X'01020304', 1, 1);
		INSERT INTO telemetry_dimension_values(id, dimension, value)
		VALUES (1, 'source', 'test');
		INSERT INTO traffic_dimension_hourly(bucket_start_utc, value_id, upload_bytes, download_bytes)
		VALUES (1, 1, 100, 200);
		INSERT INTO traffic_dimension_daily(bucket_start_utc, value_id, upload_bytes, download_bytes)
		VALUES (1, 1, 100, 200);
		INSERT INTO failure_dimension_hourly(bucket_start_utc, value_id, failed_count)
		VALUES (1, 1, 2);
		INSERT INTO failure_dimension_daily(bucket_start_utc, value_id, failed_count)
		VALUES (1, 1, 2);
		CREATE TABLE IF NOT EXISTS inbound_traffic_control (id INTEGER PRIMARY KEY CHECK(id=1), config_json TEXT NOT NULL);
		INSERT INTO inbound_traffic_control(id,config_json) VALUES(1,'{}');
		INSERT INTO user_usage_settings(id,options_json)
		VALUES (1, '{"auditDays":30,"maxAuditRows":100000,"hourlyDays":30,"dailyDays":365}');
		INSERT INTO user_usage_audit(id,user_id,credential_id,inbound_id,node_id,protocol,source,target,result,started_at,checkpoint_at,data_json)
		VALUES ('audit-1','user','','','','tcp','client','example.com:443','closed',1,2,'{"result":"closed"}');
		INSERT INTO user_usage_totals(user_id,credential_id,inbound_id,node_id,protocol,inbound_name,node_name,first_seen,last_seen)
		VALUES ('user','','','','tcp','','',1,2);
		INSERT INTO user_usage_buckets(period,bucket,user_id,credential_id,inbound_id,node_id,protocol,inbound_name,node_name,first_seen,last_seen)
		VALUES ('hour',3600,'user','','','','tcp','','',1,2);
		INSERT INTO user_usage_activity(user_id,minute) VALUES ('user',1);
		INSERT INTO user_usage_users(user_id,active_minutes) VALUES ('user',1);
		INSERT INTO user_usage_flush(id,batch_id) VALUES (1,'batch-1');
		INSERT INTO gateway_statistics(gateway_id,requests,blocked,forwarded,errors,tls_failures,protocol_failures,duration_ns,updated_at)
		VALUES ('gateway',1,0,1,0,0,0,10,1);
		INSERT INTO inbound_statistics(inbound_id,accepted_streams,received_packets,received_pings,updated_at)
		VALUES ('inbound',1,0,0,1);
	`); err != nil {
		t.Fatalf("write runtime state failed: %v", err)
	}

	backup := &Backup{dir: dir}
	first, err := readBackupSnapshot(t, backup)
	if err != nil {
		t.Fatalf("snapshot first sqlite backup failed: %v", err)
	}
	second, err := readBackupSnapshot(t, backup)
	if err != nil {
		t.Fatalf("snapshot second sqlite backup failed: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("identical configuration snapshots differ")
	}
	firstHash := calculateBytesHash(first, contractbackup.S3{})
	secondHash := calculateBytesHash(second, contractbackup.S3{})
	if firstHash != secondHash {
		t.Fatalf("identical configuration snapshot hashes differ: %s != %s", firstHash, secondHash)
	}

	// Runtime-only updates must not invalidate the S3 snapshot hash.
	if _, err := db.Exec(`
		UPDATE user_usage_audit SET checkpoint_at = 3, data_json = '{"result":"closed","upload":"100"}' WHERE id = 'audit-1';
		INSERT INTO user_usage_audit(id,user_id,credential_id,inbound_id,node_id,protocol,source,target,result,started_at,checkpoint_at,data_json)
		VALUES ('audit-2','user','','','','tcp','client','example.net:443','closed',3,4,'{"result":"closed"}');
		UPDATE gateway_statistics SET requests = 2, updated_at = 3 WHERE gateway_id = 'gateway';
		UPDATE inbound_statistics SET accepted_streams = 2, updated_at = 3 WHERE inbound_id = 'inbound';
	`); err != nil {
		t.Fatalf("update runtime-only state failed: %v", err)
	}
	third, err := readBackupSnapshot(t, backup)
	if err != nil {
		t.Fatalf("snapshot after runtime-only updates failed: %v", err)
	}
	if !bytes.Equal(first, third) {
		t.Fatal("runtime-only updates changed the configuration snapshot")
	}

	snapshotPath := filepath.Join(t.TempDir(), "state.db")
	if err := os.WriteFile(snapshotPath, first, 0o600); err != nil {
		t.Fatalf("write sanitized snapshot failed: %v", err)
	}
	snapshotStore, err := storagesqlite.Open(t.Context(), snapshotPath)
	if err != nil {
		t.Fatalf("open sanitized snapshot failed: %v", err)
	}
	defer snapshotStore.Close()

	for _, table := range []string{"statistics_kv", "traffic_hourly", "connection_history", "fakeip_entries", "telemetry_dimension_values", "traffic_dimension_hourly", "traffic_dimension_daily", "failure_dimension_hourly", "failure_dimension_daily", "user_usage_audit", "user_usage_totals", "user_usage_buckets", "user_usage_activity", "user_usage_users", "user_usage_flush", "gateway_statistics", "inbound_statistics"} {
		var count int
		if err := snapshotStore.DB().QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil {
			t.Fatalf("count sanitized table %s failed: %v", table, err)
		}
		if count != 0 {
			t.Fatalf("sanitized table %s has %d rows", table, count)
		}
	}

	var backupData string
	if err := snapshotStore.DB().QueryRow(`SELECT data_json FROM backup_settings WHERE id = 1`).Scan(&backupData); err != nil {
		t.Fatalf("read sanitized backup settings failed: %v", err)
	}
	gotBackup, err := backupstore.New(snapshotStore.DB()).Get(t.Context())
	if err != nil {
		t.Fatalf("decode sanitized backup settings failed: %v", err)
	}
	if gotBackup.LastBackupHash != "" {
		t.Fatalf("sanitized backup hash = %q, want empty; data=%s", gotBackup.LastBackupHash, backupData)
	}
	if gotBackup.Interval != 30 {
		t.Fatalf("sanitized backup interval = %d, want 30", gotBackup.Interval)
	}
	var savedUsageOptions string
	if err := snapshotStore.DB().QueryRow(`SELECT options_json FROM user_usage_settings WHERE id=1`).Scan(&savedUsageOptions); err != nil {
		t.Fatalf("read preserved usage settings failed: %v", err)
	}
	if !strings.Contains(savedUsageOptions, `"maxAuditRows":100000`) {
		t.Fatalf("usage settings were not preserved: %s", savedUsageOptions)
	}
	var savedTrafficControl string
	if err := snapshotStore.DB().QueryRow(`SELECT config_json FROM inbound_traffic_control WHERE id=1`).Scan(&savedTrafficControl); err != nil {
		t.Fatalf("read preserved inbound traffic control failed: %v", err)
	}
	if savedTrafficControl != "{}" {
		t.Fatalf("inbound traffic control was not preserved: %s", savedTrafficControl)
	}
	var localAuditCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM user_usage_audit`).Scan(&localAuditCount); err != nil {
		t.Fatal(err)
	}
	if localAuditCount != 2 {
		t.Fatalf("backup altered local audit history: got %d rows", localAuditCount)
	}
}

// New schema migrations must be explicitly classified as configuration or
// runtime data, instead of automatically leaking unknown tables to S3.
func TestBackupSQLiteRejectsUnclassifiedTable(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store, err := storagesqlite.Open(t.Context(), paths.PathGenerator.State(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.DB().Exec(`CREATE TABLE unexpected_events (event TEXT)`); err != nil {
		t.Fatal(err)
	}

	_, err = readBackupSnapshot(t, &Backup{dir: dir})
	if err == nil || !strings.Contains(err.Error(), `unclassified backup table "unexpected_events"`) {
		t.Fatalf("expected unclassified table error, got %v", err)
	}
}

func readBackupSnapshot(t *testing.T, b *Backup) ([]byte, error) {
	t.Helper()
	snapshot, err := b.snapshotStateDB(t.Context())
	if err != nil {
		return nil, err
	}
	defer snapshot.Close()
	return io.ReadAll(snapshot)
}
