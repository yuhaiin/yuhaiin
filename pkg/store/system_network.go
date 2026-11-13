package store

import (
	"context"
	"database/sql"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
)

// SystemNetworkStore persists the System Network configuration as one JSON
// document in settings_kv, so it is part of configuration backups.
type SystemNetworkStore struct {
	db *sql.DB
}

func NewSystemNetworkStore(db *sql.DB) *SystemNetworkStore { return &SystemNetworkStore{db: db} }

const systemNetworkSection, systemNetworkKey = "system_network", "config"

func (s *SystemNetworkStore) LoadSystemNetwork(ctx context.Context) (sysnet.Config, error) {
	config := sysnet.Config{Routes: []sysnet.RouteRule{}, Forwarding: sysnet.Forwarding{Rules: []sysnet.ForwardRule{}}}
	if s == nil || s.db == nil {
		return config, errors.New("system network store database is nil")
	}
	var data string
	err := s.db.QueryRowContext(ctx, `SELECT value_json FROM settings_kv WHERE section = ? AND key = ?`, systemNetworkSection, systemNetworkKey).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return config, nil
	}
	if err != nil {
		return config, fmt.Errorf("query system network settings failed: %w", err)
	}
	if err := json.Unmarshal([]byte(data), &config); err != nil {
		return config, fmt.Errorf("decode system network settings failed: %w", err)
	}
	if config.Routes == nil {
		config.Routes = []sysnet.RouteRule{}
	}
	if config.Forwarding.Rules == nil {
		config.Forwarding.Rules = []sysnet.ForwardRule{}
	}
	return config, nil
}

func (s *SystemNetworkStore) SaveSystemNetwork(ctx context.Context, config sysnet.Config) error {
	if s == nil || s.db == nil {
		return errors.New("system network store database is nil")
	}
	if err := config.Validate(); err != nil {
		return err
	}
	data, err := json.Marshal(config)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO settings_kv(section, key, value_json, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(section, key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at
	`, systemNetworkSection, systemNetworkKey, string(data), time.Now().Unix())
	if err != nil {
		return fmt.Errorf("save system network settings failed: %w", err)
	}
	return nil
}
