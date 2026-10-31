package store

import (
	"context"
	"database/sql"
	"encoding/json/v2"
	"errors"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
)

type MonitoringStore struct{ db *sql.DB }

func NewMonitoringStore(db *sql.DB) *MonitoringStore { return &MonitoringStore{db} }
func (s *MonitoringStore) Get(ctx context.Context) (contract.MonitoringConfig, error) {
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT data_json FROM node_monitoring_settings WHERE id=1`).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return contract.MonitoringConfig{}.Effective(), nil
	}
	if err != nil {
		return contract.MonitoringConfig{}, err
	}
	var c contract.MonitoringConfig
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		return c, err
	}
	return c.Effective(), c.Validate()
}
func (s *MonitoringStore) Save(ctx context.Context, c contract.MonitoringConfig) error {
	if err := c.Validate(); err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var raw string
	err = tx.QueryRowContext(ctx, `SELECT data_json FROM node_monitoring_settings WHERE id=1`).Scan(&raw)
	var current contract.MonitoringConfig
	if err == nil {
		if err := json.Unmarshal([]byte(raw), &current); err != nil {
			return err
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if c.Revision != current.Revision {
		return ErrConflict
	}
	c.Revision++
	c = c.Effective()
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO node_monitoring_settings(id,data_json) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET data_json=excluded.data_json`, string(data)); err != nil {
		return err
	}
	return tx.Commit()
}
