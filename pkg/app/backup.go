package app

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/chore"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/api"
	"github.com/Asutorufa/yuhaiin/pkg/protos/backup"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/tools"
	"github.com/Asutorufa/yuhaiin/pkg/s3"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	"github.com/Asutorufa/yuhaiin/pkg/utils/id"
	"golang.org/x/crypto/blake2b"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/emptypb"
)

type Backup struct {
	api.UnimplementedBackupServer
	db       chore.DB
	proxy    netapi.Proxy
	instance *AppInstance
	ticker   *time.Ticker
	mu       sync.Mutex
}

func NewBackup(db chore.DB, instance *AppInstance, proxy netapi.Proxy) *Backup {
	b := &Backup{
		db:       db,
		instance: instance,
		proxy:    proxy,
	}

	b.resetTicker()

	return b
}

func (b *Backup) Save(ctx context.Context, opt *config.BackupOption) (*emptypb.Empty, error) {
	err := b.db.Batch(func(s *config.Setting) error {
		s.SetBackup(opt)
		return nil
	})
	if err != nil {
		return nil, err
	}

	b.resetTicker()

	return &emptypb.Empty{}, nil
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

	if opt.GetInterval() == 0 {
		return
	}

	b.ticker = time.NewTicker(time.Duration(opt.GetInterval()) * time.Minute)

	log.Info("start new backup ticker", "interval", time.Duration(opt.GetInterval())*time.Minute)

	go func() {
		for range b.ticker.C {
			_, err := b.Backup(context.Background(), &emptypb.Empty{})
			if err != nil {
				log.Error("backup failed", "err", err)
			}
		}
	}()
}

func (b *Backup) Get(context.Context, *emptypb.Empty) (*config.BackupOption, error) {
	var cc *config.BackupOption
	_ = b.db.Batch(func(s *config.Setting) error {
		cc = s.GetBackup()

		if cc == nil {
			cc = &config.BackupOption{}
		}

		if cc.GetS3() == nil {
			cc.SetS3(config.S3_builder{
				Enabled:      new(false),
				AccessKey:    new(""),
				SecretKey:    new(""),
				Bucket:       new(""),
				EndpointUrl:  new(""),
				Region:       new(""),
				UsePathStyle: new(false),
			}.Build())
		}

		if cc.GetInstanceName() == "" {
			cc.SetInstanceName(id.GenerateUUID().String())
		}

		return nil
	})

	return cc, nil
}

func (b *Backup) Backup(ctx context.Context, opt *emptypb.Empty) (*emptypb.Empty, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	backupConfig, err := b.getConfig()
	if err != nil {
		return nil, err
	}

	s3, err := s3.NewS3(backupConfig.GetS3(), b.proxy)
	if err != nil {
		return nil, err
	}

	stateBytes, err := b.snapshotStateDB(ctx)
	if err != nil {
		return nil, err
	}

	newHash := calculateBytesHash(stateBytes, backupConfig.GetS3())
	if backupConfig.GetLastBackupHash() != "" && backupConfig.GetLastBackupHash() == newHash {
		return &emptypb.Empty{}, nil
	}

	if err := s3.Put(ctx, stateBytes, backupConfig.GetInstanceName()+"-state.db"); err != nil {
		return nil, err
	}

	if err := b.db.Batch(func(s *config.Setting) error {
		s.GetBackup().SetLastBackupHash(newHash)
		return nil
	}); err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}

func (b *Backup) Restore(ctx context.Context, _ *backup.RestoreOption) (*emptypb.Empty, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	backupConfig, err := b.getConfig()
	if err != nil {
		return nil, err
	}

	s3, err := s3.NewS3(backupConfig.GetS3(), b.proxy)
	if err != nil {
		return nil, err
	}

	stateData, err := s3.Get(ctx, backupConfig.GetInstanceName()+"-state.db")
	if err != nil {
		return nil, err
	}

	if err := b.restoreStateDB(stateData); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (b *Backup) snapshotStateDB(ctx context.Context) ([]byte, error) {
	statePath := tools.PathGenerator.State(b.db.Dir())
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
	statePath := tools.PathGenerator.State(b.db.Dir())
	dir := filepath.Dir(statePath)
	tmpPath := filepath.Join(dir, fmt.Sprintf(".state-restore-%d.db", time.Now().UnixNano()))

	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return fmt.Errorf("write sqlite restore temp file failed: %w", err)
	}
	defer func() { _ = os.Remove(tmpPath) }()

	if closer, ok := b.db.(interface{ Close() error }); ok {
		if err := closer.Close(); err != nil {
			return fmt.Errorf("close sqlite state before restore failed: %w", err)
		}
	}

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

func calculateBytesHash(content []byte, options *config.S3) string {
	s3bytes, err := protojson.Marshal(options)
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

func (b *Backup) getConfig() (*config.BackupOption, error) {
	var cc *config.BackupOption
	_ = b.db.Batch(func(s *config.Setting) error {
		cc = s.GetBackup()
		return nil
	})

	if cc == nil {
		return nil, errors.New("backup config is empty")
	}

	if cc.GetInstanceName() == "" {
		return nil, errors.New("instance name is empty")
	}

	if cc.GetS3() == nil {
		return nil, errors.New("s3 config is empty")
	}

	return cc, nil
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
