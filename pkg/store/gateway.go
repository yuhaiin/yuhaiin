package store

import (
	"context"
	"database/sql"
	json "encoding/json/v2"
	"errors"
	"fmt"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
	"github.com/Asutorufa/yuhaiin/pkg/contract/route"
)

type GatewayStore struct{ db *sql.DB }

func NewGatewayStore(db *sql.DB) *GatewayStore { return &GatewayStore{db} }

func (s *GatewayStore) Load(ctx context.Context) (contract.Config, error) {
	var data string
	err := s.db.QueryRowContext(ctx, `SELECT data_json FROM gateway_configuration WHERE id=1`).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return contract.Config{Gateways: []contract.Gateway{}, Rules: []contract.Rule{}, Upstreams: []contract.Upstream{}, Interceptions: []contract.Interception{}, FilterLists: []contract.FilterList{}}, nil
	}
	if err != nil {
		return contract.Config{}, err
	}
	var document contract.Workspace
	if err := json.Unmarshal([]byte(data), &document); err != nil {
		return contract.Config{}, err
	}
	return contract.ConfigFromWorkspace(document)
}

// Save commits the complete, validated configuration and all external resource
// references together. The runtime prepares first and swaps only after success.
func (s *GatewayStore) Save(ctx context.Context, cfg contract.Config) (contract.Config, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return cfg, err
	}
	defer func() { _ = tx.Rollback() }()
	var revision uint64
	err = tx.QueryRowContext(ctx, `SELECT revision FROM gateway_configuration WHERE id=1`).Scan(&revision)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return cfg, err
	}
	if cfg.Revision != revision {
		return cfg, ErrConflict
	}
	retained := make(map[string]bool, len(cfg.Gateways))
	for _, g := range cfg.Gateways {
		retained[g.ID] = true
	}
	rows, err := tx.QueryContext(ctx, `SELECT json_extract(g.value, '$.id') FROM gateway_configuration, json_each(data_json, '$.gateways') g`)
	if err != nil {
		return cfg, err
	}
	var removed []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return cfg, err
		}
		if !retained[id] {
			removed = append(removed, id)
		}
	}
	err = errors.Join(rows.Err(), rows.Close())
	if err != nil {
		return cfg, err
	}
	for _, id := range removed {
		refs, err := targetReferences(ctx, tx, "gateway", id)
		if err != nil {
			return cfg, err
		}
		if len(refs) > 0 {
			return cfg, &ResourceInUseError{References: refs}
		}
		// Remove lifetime counters in the same transaction as the owner.
		// Manager serializes this commit against periodic statistics flushes.
		if _, err := tx.ExecContext(ctx, `DELETE FROM gateway_statistics WHERE gateway_id=?`, id); err != nil {
			return cfg, err
		}
	}
	cfg.Revision++
	workspace, err := contract.WorkspaceFromConfig(cfg)
	if err != nil {
		return cfg, err
	}
	data, err := json.Marshal(workspace)
	if err != nil {
		return cfg, err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM gateway_references`); err != nil {
		return cfg, err
	}
	ref := func(owner, name, kind, id string) error {
		if id == "" {
			return errors.New("empty gateway resource reference")
		}
		var nodeID, selectorID, inboundID any
		switch kind {
		case "node":
			nodeID = id
		case "selector":
			selectorID = id
		case "inbound":
			inboundID = id
		default:
			return errors.New("invalid gateway resource reference")
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO gateway_references(owner_id,owner_name,node_id,selector_id,inbound_id) VALUES(?,?,?,?,?)`, owner, name, nodeID, selectorID, inboundID)
		if err != nil {
			return fmt.Errorf("gateway %s references missing %s %s: %w", owner, kind, id, err)
		}
		return nil
	}
	target := func(id, name string, t route.Target) error {
		if t.Type == "node" || t.Type == "selector" {
			return ref(id, name, t.Type, t.ID)
		}
		return nil
	}
	var conditionRefs func(string, string, contract.Condition) error
	conditionRefs = func(id, name string, c contract.Condition) error {
		if c.Field == "inbound" {
			if c.Operator != "" && c.Operator != "exact" {
				return errors.New("inbound conditions require exact IDs")
			}
			for _, inboundID := range contract.NormalizeCondition(c).Values {
				if err := ref(id, name, "inbound", inboundID); err != nil {
					return err
				}
			}
		}
		for _, child := range c.All {
			if err := conditionRefs(id, name, child); err != nil {
				return err
			}
		}
		for _, child := range c.Any {
			if err := conditionRefs(id, name, child); err != nil {
				return err
			}
		}
		if c.Not != nil {
			return conditionRefs(id, name, *c.Not)
		}
		return nil
	}
	for _, g := range cfg.Gateways {
		if err := target(g.ID, g.Name, g.Default.Outbound); err != nil {
			return cfg, err
		}
	}
	for _, r := range cfg.Rules {
		if err := target(r.ID, r.Name, r.Action.Outbound); err != nil {
			return cfg, err
		}
		if err := conditionRefs(r.ID, r.Name, r.Match); err != nil {
			return cfg, err
		}
	}
	for _, u := range cfg.Upstreams {
		if err := target(u.ID, u.Name, u.Outbound); err != nil {
			return cfg, err
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO gateway_configuration(id,revision,data_json) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,data_json=excluded.data_json`, cfg.Revision, string(data))
	if err != nil {
		return cfg, err
	}
	return cfg, tx.Commit()
}

// CA material is deliberately excluded from ordinary configuration and backups.
func (s *GatewayStore) LoadCA(ctx context.Context) ([]byte, []byte, uint64, error) {
	var cert, key []byte
	var revision uint64
	err := s.db.QueryRowContext(ctx, `SELECT certificate_pem,private_key_pem,revision FROM gateway_ca WHERE id=1`).Scan(&cert, &key, &revision)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, 0, nil
	}
	return cert, key, revision, err
}
func (s *GatewayStore) SaveCA(ctx context.Context, cert, key []byte, revision uint64) (uint64, error) {
	var result sql.Result
	var err error
	if revision == 0 {
		result, err = s.db.ExecContext(ctx, `INSERT INTO gateway_ca(id,certificate_pem,private_key_pem,revision) VALUES(1,?,?,1) ON CONFLICT(id) DO NOTHING`, cert, key)
	} else {
		result, err = s.db.ExecContext(ctx, `UPDATE gateway_ca SET certificate_pem=?,private_key_pem=?,revision=revision+1 WHERE id=1 AND revision=?`, cert, key, revision)
	}

	if err != nil {
		return revision, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return revision, err
	}
	if n == 0 {
		return revision, ErrConflict
	}
	return revision + 1, nil
}
