package store

import (
	"context"
	"database/sql"
	json "encoding/json/v2"
	"errors"
	"fmt"

	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol"
)

func (s *InboundStore) trafficControlTable(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("inbound store database is nil")
	}
	_, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS inbound_traffic_control (
			id INTEGER PRIMARY KEY CHECK(id=1),
			config_json TEXT NOT NULL
		)`)
	return err
}

// TrafficControl returns an opt-in configuration. Missing rows preserve the
// historical behavior: no bandwidth cap, no profile selection.
func (s *InboundStore) TrafficControl(ctx context.Context) (trafficcontrol.Config, error) {
	if err := s.trafficControlTable(ctx); err != nil {
		return trafficcontrol.Config{}, err
	}
	var raw string
	err := s.db.QueryRowContext(ctx, "SELECT config_json FROM inbound_traffic_control WHERE id=1").Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return trafficcontrol.Config{}, nil
	}
	if err != nil {
		return trafficcontrol.Config{}, fmt.Errorf("read traffic control: %w", err)
	}
	var cfg trafficcontrol.Config
	if err = json.Unmarshal([]byte(raw), &cfg); err != nil {
		return trafficcontrol.Config{}, fmt.Errorf("decode traffic control: %w", err)
	}
	// A corrupted historical row must never silently enable a bad policy.
	if err := trafficcontrol.ValidateConfig(cfg); err != nil {
		return trafficcontrol.Config{}, err
	}
	return cfg, nil
}

func (s *InboundStore) SaveTrafficControl(ctx context.Context, cfg trafficcontrol.Config) error {
	if err := trafficcontrol.ValidateConfig(cfg); err != nil {
		return err
	}
	if err := s.trafficControlTable(ctx); err != nil {
		return err
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("encode traffic control: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO inbound_traffic_control(id,config_json) VALUES(1,?)
		ON CONFLICT(id) DO UPDATE SET config_json=excluded.config_json`, string(raw))
	if err != nil {
		return fmt.Errorf("save traffic control: %w", err)
	}
	return nil
}
