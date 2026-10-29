package app

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	contractbackup "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/paths"
	"github.com/Asutorufa/yuhaiin/pkg/s3"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
	"golang.org/x/crypto/blake2b"
)

type Backup struct {
	store      *plainstore.BackupStore
	dir        string
	proxy      netapi.Proxy
	instance   *AppInstance
	ticker     *time.Ticker
	tickerStop chan struct{}
	mu         sync.Mutex
}

// Only these tables contain configuration that must survive a config restore.
// Keep this list explicit so new SQLite tables cannot silently add high-churn,
// potentially sensitive runtime data to S3 backups. SQLite internal tables are
// managed by SQLite itself; the FTS5 shadow tables belong to the retained nodes
// search index.
var backupConfigTables = map[string]struct{}{
	"metadata": {}, "migrate": {},
	"android_extra_preferences": {}, "settings_kv": {},
	"dns_settings": {}, "dns_resolvers": {}, "dns_hosts": {}, "dns_fakedns_lists": {},
	"inbound_settings": {}, "inbounds": {}, "nodes": {}, "node_tags": {},
	"nodes_fts": {}, "nodes_fts_config": {}, "nodes_fts_data": {},
	"nodes_fts_docsize": {}, "nodes_fts_idx": {},
	"subscriptions": {}, "publishes": {}, "route_settings": {}, "route_rules": {},
	"route_lists": {}, "route_list_refresh": {}, "backup_settings": {},
	"settings_json": {}, "inbounds_v2": {}, "nodes_v2": {},
	"node_tags_v2": {}, "resolvers_v2": {}, "route_rules_v2": {},
	"route_lists_v2": {}, "route_registries": {}, "outbound_selectors": {},
	"gateway_configuration": {}, "gateway_references": {}, "gateway_ca": {},
	"user_usage_settings": {},
}

// These tables contain runtime observations, not restorable configuration.
// Clear their rows from the snapshot but retain their schemas for direct
// state.db restore compatibility. The original local database is untouched.
var backupRuntimeTables = []string{
	"statistics_kv",
	"traffic_hourly",
	"connection_sessions",
	"connection_history",
	"failed_connection_history",
	"fakeip_entries",
	"fakeip_cursors",
	"fakeip_pool_counts",
	"traffic_dimension_hourly",
	"traffic_dimension_daily",
	"failure_dimension_hourly",
	"failure_dimension_daily",
	"telemetry_dimension_values",
	"gateway_statistics",
	"inbound_statistics",
	"node_runtime_stats",
	"user_usage_totals",
	"user_usage_buckets",
	"user_usage_activity",
	"user_usage_users",
	"user_usage_audit",
	"user_usage_flush",
}

func NewBackup(store *plainstore.BackupStore, dir string, instance *AppInstance, proxy netapi.Proxy) *Backup {
	b := &Backup{
		store:    store,
		dir:      dir,
		instance: instance,
		proxy:    proxy,
	}

	b.resetTicker()

	return b
}

func (b *Backup) Save(ctx context.Context, opt contractbackup.Option) (contractbackup.Option, error) {
	if b.store == nil {
		return contractbackup.Option{}, fmt.Errorf("backup store is unavailable")
	}
	if err := b.store.Save(ctx, opt); err != nil {
		return contractbackup.Option{}, err
	}

	b.resetTicker()

	return b.store.Get(ctx)
}

func (b *Backup) resetTicker() {
	b.mu.Lock()
	defer b.mu.Unlock()

	opt, err := b.getConfig()
	if err != nil {
		log.Error("get config failed", "err", err)
		return
	}

	b.stopTicker()

	if opt.Interval == 0 {
		return
	}

	ticker := time.NewTicker(time.Duration(opt.Interval) * time.Minute)
	stop := make(chan struct{})
	b.ticker = ticker
	b.tickerStop = stop

	log.Info("start new backup ticker", "interval", time.Duration(opt.Interval)*time.Minute)

	go func() {
		for {
			select {
			case <-ticker.C:
				if err := b.Run(context.Background()); err != nil {
					log.Error("backup failed", "err", err)
				}
			case <-stop:
				return
			}
		}
	}()
}

// stopTicker is called with b.mu held. Stop does not close a ticker channel,
// so also signal its worker to exit when the backup interval changes.
func (b *Backup) stopTicker() {
	if b.ticker != nil {
		b.ticker.Stop()
		close(b.tickerStop)
		b.ticker = nil
		b.tickerStop = nil
	}
}

func (b *Backup) Get(context.Context) (contractbackup.Option, error) {
	if b.store == nil {
		return contractbackup.Option{}, fmt.Errorf("backup store is unavailable")
	}
	return b.store.Get(context.Background())
}

func (b *Backup) Run(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	backupConfig, err := b.getConfig()
	if err != nil {
		return err
	}

	s3, err := s3.NewS3(backupConfig.S3, b.proxy)
	if err != nil {
		return err
	}

	stateBytes, err := b.snapshotStateDB(ctx)
	if err != nil {
		return err
	}

	newHash := calculateBytesHash(stateBytes, backupConfig.S3)
	if backupConfig.LastBackupHash != "" && backupConfig.LastBackupHash == newHash {
		return nil
	}

	if err := s3.Put(ctx, stateBytes, backupConfig.InstanceName+"-state.db"); err != nil {
		return err
	}

	if err := b.store.SaveHash(ctx, newHash); err != nil {
		return err
	}

	return nil
}

func (b *Backup) Restore(ctx context.Context, _ contractbackup.RestoreOption) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	backupConfig, err := b.getConfig()
	if err != nil {
		return err
	}

	s3, err := s3.NewS3(backupConfig.S3, b.proxy)
	if err != nil {
		return err
	}

	stateData, err := s3.Get(ctx, backupConfig.InstanceName+"-state.db")
	if err != nil {
		return err
	}

	if err := b.restoreStateDB(stateData); err != nil {
		return err
	}
	return nil
}

func (b *Backup) snapshotStateDB(ctx context.Context) ([]byte, error) {
	statePath := paths.PathGenerator.State(b.dir)
	tmpPath := filepath.Join(filepath.Dir(statePath), fmt.Sprintf(".state-backup-%d.db", time.Now().UnixNano()))
	defer func() { _ = os.Remove(tmpPath) }()

	store, err := storagesqlite.Open(ctx, statePath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite for backup failed: %w", err)
	}
	defer store.Close()

	if _, err := store.DB().ExecContext(ctx, "VACUUM INTO '"+sqliteStringLiteral(tmpPath)+"'"); err != nil {
		return nil, fmt.Errorf("snapshot sqlite backup failed: %w", err)
	}

	if err := sanitizeBackupSnapshot(ctx, tmpPath); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(tmpPath)
	if err != nil {
		return nil, fmt.Errorf("read sqlite backup snapshot failed: %w", err)
	}

	return data, nil
}

func sanitizeBackupSnapshot(ctx context.Context, path string) error {
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

	if err := validateBackupSnapshotTables(ctx, tx); err != nil {
		return err
	}
	for _, table := range backupRuntimeTables {
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+table); err != nil {
			return fmt.Errorf("clear runtime table %s from backup snapshot failed: %w", table, err)
		}
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
		var opt contractbackup.Option
		if err := json.Unmarshal([]byte(data), &opt); err != nil {
			return fmt.Errorf("decode backup settings from backup snapshot failed: %w", err)
		}
		opt.LastBackupHash = ""
		normalized, err := json.Marshal(opt)
		if err != nil {
			return fmt.Errorf("encode normalized backup settings failed: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE backup_settings
			SET updated_at = 0, data_json = ?
			WHERE id = 1
		`, string(normalized)); err != nil {
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

// validateBackupSnapshotTables fails closed when a migration introduces an
// unclassified table. A backup must never upload newly added runtime/audit
// data merely because someone forgot to update the exclusion list.
func validateBackupSnapshotTables(ctx context.Context, tx *sql.Tx) error {
	runtimeTables := make(map[string]struct{}, len(backupRuntimeTables))
	for _, table := range backupRuntimeTables {
		runtimeTables[table] = struct{}{}
	}
	rows, err := tx.QueryContext(ctx, "SELECT name FROM sqlite_master WHERE type='table'")
	if err != nil {
		return fmt.Errorf("list backup tables failed: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return fmt.Errorf("scan backup table failed: %w", err)
		}
		if strings.HasPrefix(name, "sqlite_") {
			continue
		}
		if _, ok := backupConfigTables[name]; ok {
			continue
		}
		if _, ok := runtimeTables[name]; !ok {
			return fmt.Errorf("unclassified backup table %q: classify it as configuration or runtime data", name)
		}
	}
	return rows.Err()
}

func (b *Backup) restoreStateDB(data []byte) error {
	statePath := paths.PathGenerator.State(b.dir)
	dir := filepath.Dir(statePath)
	tmpPath := filepath.Join(dir, fmt.Sprintf(".state-restore-%d.db", time.Now().UnixNano()))

	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return fmt.Errorf("write sqlite restore temp file failed: %w", err)
	}
	defer func() { _ = os.Remove(tmpPath) }()

	if err := os.Rename(tmpPath, statePath); err != nil {
		return fmt.Errorf("replace sqlite state db failed: %w", err)
	}

	_ = os.Remove(statePath + "-wal")
	_ = os.Remove(statePath + "-shm")

	log.Warn("sqlite state restored; restart is required for all in-memory services to reload restored data")
	return nil
}

func sqliteStringLiteral(path string) string {
	return strings.ReplaceAll(path, "'", "''")
}

func calculateBytesHash(content []byte, options contractbackup.S3) string {
	s3bytes, err := json.Marshal(options)
	if err != nil {
		log.Warn("marshal s3 failed", "err", err)
		return ""
	}

	hash, err := blake2b.New(32, nil)
	if err != nil {
		log.Warn("new blake2b hash failed", "err", err)
		return ""
	}

	hash.Write(content)
	hash.Write(s3bytes)
	return hex.EncodeToString(hash.Sum(nil))
}

func (b *Backup) getConfig() (contractbackup.Option, error) {
	if b.store == nil {
		return contractbackup.Option{}, fmt.Errorf("backup store is unavailable")
	}
	return b.store.Runtime(context.Background())
}

func (b *Backup) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.stopTicker()

	return nil
}
