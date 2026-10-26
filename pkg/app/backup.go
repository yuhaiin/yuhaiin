package app

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	contractbackup "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/paths"
	s3pkg "github.com/Asutorufa/yuhaiin/pkg/s3"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
	"golang.org/x/crypto/blake2b"
)

type Backup struct {
	store           *plainstore.BackupStore
	dir             string
	proxy           netapi.Proxy
	instance        *AppInstance
	mu              sync.Mutex
	scheduleMu      sync.Mutex
	ctx             context.Context
	cancel          context.CancelFunc
	done            chan struct{}
	changed         chan struct{}
	scheduledCancel context.CancelFunc
}

// These tables contain runtime data which changes frequently but is not needed
// to restore the user's proxy configuration. Keeping their schemas in the
// backup preserves direct state.db restore compatibility while avoiding the
// repeated upload of traffic and connection history.
var backupRuntimeTables = []string{
	"statistics_kv",
	"traffic_hourly",
	"connection_sessions",
	"connection_history",
	"failed_connection_history",
	"fakeip_entries",
	"fakeip_cursors",
	"traffic_dimension_hourly",
	"traffic_dimension_daily",
	"failure_dimension_hourly",
	"failure_dimension_daily",
	"telemetry_dimension_values",
}

func NewBackup(store *plainstore.BackupStore, dir string, instance *AppInstance, proxy netapi.Proxy) *Backup {
	b := &Backup{
		store:    store,
		dir:      dir,
		instance: instance,
		proxy:    proxy,
	}

	b.ctx, b.cancel = context.WithCancel(context.Background())
	b.done, b.changed = make(chan struct{}), make(chan struct{}, 1)
	go b.schedule()
	return b
}

func (b *Backup) Save(ctx context.Context, opt contractbackup.Option) (contractbackup.Option, error) {
	if b.store == nil {
		return contractbackup.Option{}, fmt.Errorf("backup store is unavailable")
	}
	if opt.Interval > 365*24*60 {
		return contractbackup.Option{}, errors.New("backup interval exceeds one year")
	}
	opt.LastBackupHash = ""
	if err := b.store.Save(ctx, opt); err != nil {
		return contractbackup.Option{}, err
	}

	b.reschedule()

	return b.store.Get(ctx)
}

// reschedule cancels periodic work without waiting for an upload while holding
// a settings lock. One owner goroutine manages the only scheduling timer.
func (b *Backup) reschedule() {
	b.scheduleMu.Lock()
	if b.scheduledCancel != nil {
		b.scheduledCancel()
	}
	select {
	case b.changed <- struct{}{}:
	default:
	}
	b.scheduleMu.Unlock()
}

func (b *Backup) schedule() {
	defer close(b.done)
	for {
		var tick <-chan time.Time
		var timer *time.Timer
		if b.store != nil {
			opt, err := b.store.Get(b.ctx)
			if err == nil && opt.S3.Enabled && opt.Interval > 0 && opt.Interval <= 365*24*60 {
				timer = time.NewTimer(time.Duration(opt.Interval) * time.Minute)
				tick = timer.C
			} else if err != nil && b.ctx.Err() == nil {
				// Transient store errors retry at a bounded rate, never a busy loop.
				timer = time.NewTimer(time.Minute)
				tick = timer.C
			}
		}
		select {
		case <-b.ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return
		case <-b.changed:
			if timer != nil {
				timer.Stop()
			}
			continue
		case <-tick:
		}
		ctx, cancel := context.WithTimeout(b.ctx, 10*time.Minute)
		b.scheduleMu.Lock()
		select {
		case <-b.changed:
			b.scheduleMu.Unlock()
			cancel()
			continue
		default:
		}
		b.scheduledCancel = cancel
		b.scheduleMu.Unlock()
		if err := b.Run(ctx); err != nil && ctx.Err() == nil && !errors.Is(err, errBackupBusy) {
			log.Error("backup failed", "err", err)
		}
		cancel()
		b.scheduleMu.Lock()
		b.scheduledCancel = nil
		b.scheduleMu.Unlock()
	}
}

func (b *Backup) Get(ctx context.Context) (contractbackup.Option, error) {
	if b.store == nil {
		return contractbackup.Option{}, errors.New("backup store is unavailable")
	}
	return b.store.Get(ctx)
}

var errBackupBusy = errors.New("a backup or restore is already in progress")

func (b *Backup) operationContext(ctx context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	stop := func() bool { return false }
	if b.ctx != nil {
		stop = context.AfterFunc(b.ctx, cancel)
		if b.ctx.Err() != nil {
			cancel()
		}
	}
	return ctx, func() { stop(); cancel() }
}

func (b *Backup) Run(ctx context.Context) error {
	if !b.mu.TryLock() {
		return errBackupBusy
	}
	defer b.mu.Unlock()
	ctx, cancel := b.operationContext(ctx)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	backupConfig, err := b.getConfig(ctx)
	if err != nil {
		return err
	}

	s3, err := s3pkg.NewS3(backupConfig.S3, b.proxy)
	if err != nil {
		return err
	}

	defer s3.Close()
	snapshot, err := b.snapshotStateDB(ctx)
	if err != nil {
		return err
	}

	defer snapshot.Close()
	info, err := snapshot.Stat()
	if err != nil {
		return err
	}
	if info.Size() > s3pkg.MaxObjectBytes {
		return errors.New("backup snapshot exceeds 100 GiB")
	}
	newHash, err := calculateReaderHash(ctx, snapshot, backupConfig.S3)
	if err != nil {
		return err
	}
	if backupConfig.LastBackupHash != "" && backupConfig.LastBackupHash == newHash {
		return nil
	}

	if err := s3.PutReader(ctx, snapshot, info.Size(), backupConfig.InstanceName+"-state.db"); err != nil {
		return err
	}

	// Read the object back before calling this a successful backup. ETags are
	// not reliable content hashes for multipart uploads or every S3 provider.
	verify, err := blake2b.New(32, nil)
	if err != nil {
		return err
	}
	count, err := s3.Download(ctx, verify, backupConfig.InstanceName+"-state.db", info.Size())
	if err != nil {
		return fmt.Errorf("verify uploaded backup: %w", err)
	}
	options, err := json.Marshal(backupConfig.S3)
	if err != nil {
		return err
	}
	_, _ = verify.Write(options)
	if count != info.Size() || hex.EncodeToString(verify.Sum(nil)) != newHash {
		return errors.New("uploaded backup content verification failed")
	}
	if err := b.store.SaveHashIfUnchanged(ctx, backupConfig, newHash); err != nil {
		return err
	}

	return nil
}

func (b *Backup) Restore(ctx context.Context, _ contractbackup.RestoreOption) error {
	if !b.mu.TryLock() {
		return errBackupBusy
	}
	defer b.mu.Unlock()
	ctx, cancel := b.operationContext(ctx)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := storagesqlite.RequireClosed(paths.PathGenerator.State(b.dir), filepath.Join(b.dir, "management.db")); err != nil {
		return fmt.Errorf("live SQLite replacement is prohibited; use the controlled maintenance recovery workflow: %w", err)
	}
	backupConfig, err := b.getConfig(ctx)
	if err != nil {
		return err
	}

	s3, err := s3pkg.NewS3(backupConfig.S3, b.proxy)
	if err != nil {
		return err
	}

	defer s3.Close()
	stateData, err := s3.Get(ctx, backupConfig.InstanceName+"-state.db")
	if err != nil {
		return err
	}

	if err := b.restoreStateDB(ctx, stateData); err != nil {
		return err
	}
	return nil
}

type backupSnapshot struct {
	*os.File
	directory string
}

func (s *backupSnapshot) Close() error { return errors.Join(s.File.Close(), os.RemoveAll(s.directory)) }

func (b *Backup) snapshotStateDB(ctx context.Context) (_ *backupSnapshot, resultErr error) {
	statePath := paths.PathGenerator.State(b.dir)
	directory, err := os.MkdirTemp(filepath.Dir(statePath), ".state-backup-*")
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			_ = os.RemoveAll(directory)
		}
	}()
	tmpPath := filepath.Join(directory, "state.db")

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

	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return nil, err
	}
	data, err := os.Open(tmpPath)
	if err != nil {
		return nil, fmt.Errorf("read sqlite backup snapshot failed: %w", err)
	}

	return &backupSnapshot{File: data, directory: directory}, nil
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

func (b *Backup) restoreStateDB(ctx context.Context, data []byte) error {
	return b.restoreLegacyConfiguration(ctx, data)
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

func calculateReaderHash(ctx context.Context, content io.Reader, options contractbackup.S3) (string, error) {
	config, err := json.Marshal(options)
	if err != nil {
		return "", err
	}
	hash, err := blake2b.New(32, nil)
	if err != nil {
		return "", err
	}
	buffer := make([]byte, 32<<10)
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		n, err := content.Read(buffer)
		_, _ = hash.Write(buffer[:n])
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", err
		}
	}
	_, _ = hash.Write(config)
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func (b *Backup) getConfig(ctx context.Context) (contractbackup.Option, error) {
	if b.store == nil {
		return contractbackup.Option{}, errors.New("backup store is unavailable")
	}
	return b.store.Runtime(ctx)
}

func (b *Backup) Close() error {
	if b.cancel != nil {
		b.cancel()
		<-b.done
	}
	// Active manual work inherits cancellation as well as periodic work.
	b.mu.Lock()
	defer b.mu.Unlock()
	return nil
}
