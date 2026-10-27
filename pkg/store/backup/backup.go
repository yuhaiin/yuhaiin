package backup

import (
	"context"
	"database/sql"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"time"
	"uuid"

	contractbackup "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
)

type Store struct {
	db *sql.DB
}

func New(db *sql.DB) *Store {
	return &Store{db: db}
}

func (s *Store) Get(ctx context.Context) (contractbackup.Option, error) {
	if s == nil || s.db == nil {
		return contractbackup.Option{}, errors.New("backup store database is nil")
	}
	opt, err := s.load(ctx)
	if err != nil {
		return contractbackup.Option{}, err
	}
	if opt.InstanceName == "" {
		opt.InstanceName = uuid.New().String()
		data, err := json.Marshal(opt)
		if err != nil {
			return contractbackup.Option{}, err
		}
		// Initialization may race a settings save or another reader. Fill only
		// the missing identifier, preserving every concurrently changed field.
		if _, err := s.db.ExecContext(ctx, `
			INSERT INTO backup_settings(id, updated_at, data_json) VALUES (1, ?, ?)
			ON CONFLICT(id) DO UPDATE SET updated_at = excluded.updated_at,
			data_json = json_set(backup_settings.data_json, '$.instanceName', json_extract(excluded.data_json, '$.instanceName'))
			WHERE COALESCE(json_extract(backup_settings.data_json, '$.instanceName'), '') = ''
		`, time.Now().Unix(), string(data)); err != nil {
			return contractbackup.Option{}, err
		}
		return s.load(ctx)
	}
	return opt, nil
}

func (s *Store) Runtime(ctx context.Context) (contractbackup.Option, error) {
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

func (s *Store) Save(ctx context.Context, opt contractbackup.Option) error {
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

func (s *Store) SaveHash(ctx context.Context, hash string) error {
	opt, err := s.Get(ctx)
	if err != nil {
		return err
	}
	opt.LastBackupHash = hash
	return s.Save(ctx, opt)
}

func (s *Store) load(ctx context.Context) (contractbackup.Option, error) {
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

// SaveHashIfUnchanged cannot overwrite settings saved during a long upload.
// A changed configuration will be backed up by the next run instead.
func (s *Store) SaveHashIfUnchanged(ctx context.Context, expected contractbackup.Option, hash string) error {
	old, err := json.Marshal(expected)
	if err != nil {
		return err
	}
	expected.LastBackupHash = hash
	updated, err := json.Marshal(expected)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE backup_settings SET updated_at = ?, data_json = ? WHERE id = 1 AND data_json = ?`, time.Now().Unix(), string(updated), string(old))
	return err
}
