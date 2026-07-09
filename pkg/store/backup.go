package store

import (
	"context"
	"database/sql"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"time"

	contractbackup "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	"github.com/Asutorufa/yuhaiin/pkg/utils/id"
)

type BackupStore struct {
	db *sql.DB
}

func NewBackupStore(db *sql.DB) *BackupStore {
	return &BackupStore{db: db}
}

func (s *BackupStore) Get(ctx context.Context) (contractbackup.Option, error) {
	if s == nil || s.db == nil {
		return contractbackup.Option{}, errors.New("backup store database is nil")
	}
	opt, err := s.load(ctx)
	if err != nil {
		return contractbackup.Option{}, err
	}
	if opt.InstanceName == "" {
		opt.InstanceName = id.GenerateUUID().String()
		if err := s.Save(ctx, opt); err != nil {
			return contractbackup.Option{}, err
		}
	}
	return opt, nil
}

func (s *BackupStore) Runtime(ctx context.Context) (contractbackup.Option, error) {
	opt, err := s.Get(ctx)
	if err != nil {
		return contractbackup.Option{}, err
	}
	if opt.InstanceName == "" {
		return contractbackup.Option{}, errors.New("instance name is empty")
	}
	if !opt.S3.Enabled {
		return contractbackup.Option{}, errors.New("s3 config is empty")
	}
	return opt, nil
}

func (s *BackupStore) Save(ctx context.Context, opt contractbackup.Option) error {
	if s == nil || s.db == nil {
		return errors.New("backup store database is nil")
	}
	data, err := json.Marshal(opt)
	if err != nil {
		return fmt.Errorf("encode backup settings failed: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO backup_settings(id, updated_at, data_json)
		VALUES (1, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			updated_at = excluded.updated_at,
			data_json = excluded.data_json
	`, time.Now().Unix(), string(data)); err != nil {
		return fmt.Errorf("save backup settings failed: %w", err)
	}
	return nil
}

func (s *BackupStore) SaveHash(ctx context.Context, hash string) error {
	opt, err := s.Get(ctx)
	if err != nil {
		return err
	}
	opt.LastBackupHash = hash
	return s.Save(ctx, opt)
}

func (s *BackupStore) load(ctx context.Context) (contractbackup.Option, error) {
	var data string
	err := s.db.QueryRowContext(ctx, `
		SELECT data_json
		FROM backup_settings
		WHERE id = 1
	`).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return contractbackup.Option{}, nil
	}
	if err != nil {
		return contractbackup.Option{}, fmt.Errorf("query backup settings failed: %w", err)
	}
	var opt contractbackup.Option
	if err := json.Unmarshal([]byte(data), &opt); err != nil {
		return contractbackup.Option{}, fmt.Errorf("decode backup settings failed: %w", err)
	}
	return opt, nil
}
