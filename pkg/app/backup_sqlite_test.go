package app

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	contractbackup "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	contractsettings "github.com/Asutorufa/yuhaiin/pkg/contract/settings"
	"github.com/Asutorufa/yuhaiin/pkg/paths"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

func TestBackupSQLiteSnapshotRestore(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sqliteStore, err := storagesqlite.Open(t.Context(), paths.PathGenerator.State(dir))
	if err != nil {
		t.Fatalf("open sqlite failed: %v", err)
	}
	settings := plainstore.NewSettingsStore(sqliteStore.DB())

	if _, err := settings.Save(t.Context(), contractsettings.Settings{NetInterface: "before"}); err != nil {
		t.Fatalf("write initial sqlite config failed: %v", err)
	}

	backup := &Backup{dir: dir}
	snapshot, err := backup.snapshotStateDB(t.Context())
	if err != nil {
		t.Fatalf("snapshot sqlite state failed: %v", err)
	}

	if _, err := settings.Save(t.Context(), contractsettings.Settings{NetInterface: "after"}); err != nil {
		t.Fatalf("write modified sqlite config failed: %v", err)
	}
	if err := sqliteStore.Close(); err != nil {
		t.Fatalf("close sqlite before restore failed: %v", err)
	}

	if err := backup.restoreStateDB(snapshot); err != nil {
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
	if err := plainstore.NewBackupStore(sqliteStore.DB()).Save(t.Context(), contractbackup.Option{
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
	first, err := backup.snapshotStateDB(t.Context())
	if err != nil {
		t.Fatalf("snapshot first sqlite backup failed: %v", err)
	}
	second, err := backup.snapshotStateDB(t.Context())
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
	third, err := backup.snapshotStateDB(t.Context())
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

	for _, table := range backupRuntimeTables {
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
	gotBackup, err := plainstore.NewBackupStore(snapshotStore.DB()).Get(t.Context())
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

	_, err = (&Backup{dir: dir}).snapshotStateDB(t.Context())
	if err == nil || !strings.Contains(err.Error(), `unclassified backup table "unexpected_events"`) {
		t.Fatalf("expected unclassified table error, got %v", err)
	}
}

func TestBackupTickerStopsWhenReconfigured(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sqliteStore, err := storagesqlite.Open(t.Context(), paths.PathGenerator.State(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer sqliteStore.Close()

	store := plainstore.NewBackupStore(sqliteStore.DB())
	backup := &Backup{store: store}
	save := func(enabled bool, interval uint64) {
		t.Helper()
		if err := store.Save(t.Context(), contractbackup.Option{
			InstanceName: "instance",
			Interval:     interval,
			S3:           contractbackup.S3{Enabled: enabled},
		}); err != nil {
			t.Fatal(err)
		}
		backup.resetTicker()
	}
	assertStopped := func(stop <-chan struct{}) {
		t.Helper()
		select {
		case <-stop:
		default:
			t.Fatal("retired backup worker was not stopped")
		}
	}

	save(true, 60)
	first := backup.tickerStop
	if first == nil {
		t.Fatal("enabled backup should have a ticker")
	}
	save(true, 30)
	assertStopped(first)
	second := backup.tickerStop
	if second == nil || second == first {
		t.Fatal("backup interval update did not replace the ticker")
	}
	save(false, 30)
	assertStopped(second)
	if backup.ticker != nil {
		t.Fatal("disabled S3 still has an active backup ticker")
	}
	save(true, 60)
	third := backup.tickerStop
	if third == nil {
		t.Fatal("re-enabled backup should have a ticker")
	}
	if err := backup.Close(); err != nil {
		t.Fatal(err)
	}
	assertStopped(third)
}
