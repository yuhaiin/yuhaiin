package app

import (
	"context"
	"encoding/hex"
	"encoding/json/v2"
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
	store    *plainstore.BackupStore
	dir      string
	proxy    netapi.Proxy
	instance *AppInstance
	ticker   *time.Ticker
	mu       sync.Mutex
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

	if b.ticker != nil {
		b.ticker.Stop()
		b.ticker = nil
	}

	if opt.Interval == 0 {
		return
	}

	b.ticker = time.NewTicker(time.Duration(opt.Interval) * time.Minute)

	log.Info("start new backup ticker", "interval", time.Duration(opt.Interval)*time.Minute)

	go func() {
		for range b.ticker.C {
			if err := b.Run(context.Background()); err != nil {
				log.Error("backup failed", "err", err)
			}
		}
	}()
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

	data, err := os.ReadFile(tmpPath)
	if err != nil {
		return nil, fmt.Errorf("read sqlite backup snapshot failed: %w", err)
	}

	return data, nil
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

	if b.ticker != nil {
		b.ticker.Stop()
		b.ticker = nil
	}

	return nil
}
