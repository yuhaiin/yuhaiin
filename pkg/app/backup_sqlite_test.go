package app

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
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
	sqliteStore, err := storagesqlite.Open(context.Background(), paths.PathGenerator.State(dir))
	if err != nil {
		t.Fatalf("open sqlite failed: %v", err)
	}
	settings := plainstore.NewSettingsStore(sqliteStore.DB())

	if _, err := settings.Save(context.Background(), contractsettings.Settings{NetInterface: "before"}); err != nil {
		t.Fatalf("write initial sqlite config failed: %v", err)
	}

	backup := &Backup{dir: dir}
	snapshot, err := backup.snapshotStateDB(context.Background())
	if err != nil {
		t.Fatalf("snapshot sqlite state failed: %v", err)
	}

	if _, err := settings.Save(context.Background(), contractsettings.Settings{NetInterface: "after"}); err != nil {
		t.Fatalf("write modified sqlite config failed: %v", err)
	}
	if err := sqliteStore.Close(); err != nil {
		t.Fatalf("close sqlite before restore failed: %v", err)
	}

	if err := backup.restoreStateDB(snapshot); err != nil {
		t.Fatalf("restore sqlite state failed: %v", err)
	}

	reopened, err := storagesqlite.Open(context.Background(), paths.PathGenerator.State(dir))
	if err != nil {
		t.Fatalf("reopen sqlite failed: %v", err)
	}
	defer reopened.Close()
	reopenedSettings := plainstore.NewSettingsStore(reopened.DB())
	got, err := reopenedSettings.Load(context.Background())
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
	sqliteStore, err := storagesqlite.Open(context.Background(), paths.PathGenerator.State(dir))
	if err != nil {
		t.Fatalf("open sqlite failed: %v", err)
	}
	defer sqliteStore.Close()

	settings := plainstore.NewSettingsStore(sqliteStore.DB())
	if _, err := settings.Save(context.Background(), contractsettings.Settings{NetInterface: "before"}); err != nil {
		t.Fatalf("write initial sqlite config failed: %v", err)
	}
	if err := plainstore.NewBackupStore(sqliteStore.DB()).Save(context.Background(), contractbackup.Option{
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
	`); err != nil {
		t.Fatalf("write runtime state failed: %v", err)
	}

	backup := &Backup{dir: dir}
	first, err := backup.snapshotStateDB(context.Background())
	if err != nil {
		t.Fatalf("snapshot first sqlite backup failed: %v", err)
	}
	second, err := backup.snapshotStateDB(context.Background())
	if err != nil {
		t.Fatalf("snapshot second sqlite backup failed: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("identical configuration snapshots differ")
	}

	snapshotPath := filepath.Join(t.TempDir(), "state.db")
	if err := os.WriteFile(snapshotPath, first, 0o600); err != nil {
		t.Fatalf("write sanitized snapshot failed: %v", err)
	}
	snapshotStore, err := storagesqlite.Open(context.Background(), snapshotPath)
	if err != nil {
		t.Fatalf("open sanitized snapshot failed: %v", err)
	}
	defer snapshotStore.Close()

	for _, table := range []string{
		"statistics_kv",
		"traffic_hourly",
		"connection_history",
		"fakeip_entries",
	} {
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
	gotBackup, err := plainstore.NewBackupStore(snapshotStore.DB()).Get(context.Background())
	if err != nil {
		t.Fatalf("decode sanitized backup settings failed: %v", err)
	}
	if gotBackup.LastBackupHash != "" {
		t.Fatalf("sanitized backup hash = %q, want empty; data=%s", gotBackup.LastBackupHash, backupData)
	}
	if gotBackup.Interval != 30 {
		t.Fatalf("sanitized backup interval = %d, want 30", gotBackup.Interval)
	}
}
