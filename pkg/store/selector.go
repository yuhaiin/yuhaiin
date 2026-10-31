package store

import (
	"context"
	"database/sql"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"
	"uuid"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
)

type SelectorStore struct{ db *sql.DB }

func NewSelectorStore(db *sql.DB) *SelectorStore { return &SelectorStore{db: db} }

func (s *SelectorStore) List(ctx context.Context) ([]contractnode.Selector, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, node_id, revision, policy_json FROM outbound_selectors ORDER BY name, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []contractnode.Selector{}
	for rows.Next() {
		var item contractnode.Selector
		var policy string
		if err := rows.Scan(&item.ID, &item.Name, &item.NodeID, &item.Revision, &policy); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(policy), &item.Policy); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *SelectorStore) Get(ctx context.Context, id string) (contractnode.Selector, error) {
	var item contractnode.Selector
	var policy string
	err := s.db.QueryRowContext(ctx, `SELECT id, name, node_id, revision, policy_json FROM outbound_selectors WHERE id = ?`, id).Scan(&item.ID, &item.Name, &item.NodeID, &item.Revision, &policy)
	if errors.Is(err, sql.ErrNoRows) {
		return item, fmt.Errorf("%w: selector %s", ErrNotFound, id)
	}
	if err != nil {
		return item, err
	}
	err = json.Unmarshal([]byte(policy), &item.Policy)
	return item, err
}

func (s *SelectorStore) Save(ctx context.Context, item contractnode.Selector) (contractnode.Selector, error) {
	item.Name = strings.TrimSpace(item.Name)
	if item.Name == "" || item.NodeID == "" {
		return item, fmt.Errorf("name and selected node are required")
	}
	if item.Policy != nil {
		if err := item.Policy.Validate(); err != nil {
			return item, err
		}
	}
	policy, err := json.Marshal(item.Policy)
	if err != nil {
		return item, err
	}
	if item.ID == "" {
		item.ID = uuid.New().String()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return item, err
	}
	defer func() { _ = tx.Rollback() }()
	node, err := getNodeContract(ctx, tx, item.NodeID)
	if err != nil {
		return item, err
	}
	if !node.Enabled {
		return item, fmt.Errorf("selected node %q is disabled", node.Name)
	}
	if item.Policy != nil {
		for _, candidate := range item.Policy.Candidates {
			if _, err := getNodeContract(ctx, tx, candidate.NodeID); err != nil {
				return item, err
			}
		}
	}
	var revision uint64
	err = tx.QueryRowContext(ctx, `SELECT revision FROM outbound_selectors WHERE id = ?`, item.ID).Scan(&revision)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return item, err
	}
	if revision != item.Revision {
		return item, ErrConflict
	}
	item.Revision++
	_, err = tx.ExecContext(ctx, `INSERT INTO outbound_selectors(id, name, node_id, revision, policy_json) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET name = excluded.name, node_id = excluded.node_id, revision = excluded.revision, policy_json = excluded.policy_json`, item.ID, item.Name, item.NodeID, item.Revision, string(policy))
	if err != nil {
		return item, err
	}
	return item, tx.Commit()
}

func (s *SelectorStore) References(ctx context.Context, id string) ([]contractroute.Reference, error) {
	return targetReferences(ctx, s.db, "selector", id)
}

func (s *SelectorStore) Delete(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	refs, err := targetReferences(ctx, tx, "selector", id)
	if err != nil {
		return err
	}
	if len(refs) > 0 {
		return &ResourceInUseError{References: refs}
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM outbound_selectors WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}

func targetReferences(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, kind, id string) ([]contractroute.Reference, error) {
	rows, err := q.QueryContext(ctx, `SELECT 'rule', id, name FROM route_rules_v2 WHERE json_extract(data_json, '$.target.type') = ? AND json_extract(data_json, '$.target.id') = ?
        UNION ALL SELECT 'default', 'route-default', 'Default routing destination' FROM route_settings
        WHERE json_extract(default_target_json, '$.type') = ? AND json_extract(default_target_json, '$.id') = ?
		UNION ALL SELECT 'rule', json_extract(r.value, '$.id'), json_extract(r.value, '$.name') || ' (running)'
		FROM route_configuration_state s, json_each(s.applied_rules_json) r
		WHERE json_extract(r.value, '$.target.type') = ? AND json_extract(r.value, '$.target.id') = ?
		AND NOT EXISTS(SELECT 1 FROM route_rules_v2 c WHERE c.id = json_extract(r.value, '$.id') AND json_extract(c.data_json, '$.target.type') = ? AND json_extract(c.data_json, '$.target.id') = ?)
		UNION ALL SELECT 'default', 'route-default', 'Default routing destination (running)' FROM route_configuration_state
		WHERE json_extract(applied_config_json, '$.defaultTarget.type') = ? AND json_extract(applied_config_json, '$.defaultTarget.id') = ?
		AND NOT EXISTS(SELECT 1 FROM route_settings WHERE json_extract(default_target_json, '$.type') = ? AND json_extract(default_target_json, '$.id') = ?)
 UNION ALL SELECT 'gateway', owner_id, owner_name FROM gateway_references WHERE (?='node' AND node_id=?) OR (?='selector' AND selector_id=?)`, kind, id, kind, id, kind, id, kind, id, kind, id, kind, id, kind, id, kind, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	refs := []contractroute.Reference{}
	for rows.Next() {
		ref := contractroute.Reference{Kind: "rule"}
		if err := rows.Scan(&ref.Kind, &ref.ID, &ref.Name); err != nil {
			return nil, err
		}
		refs = append(refs, ref)
	}
	return refs, rows.Err()
}

// NodeReferences protects both direct destinations and shared node choices.
func NodeReferences(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, id string) ([]contractroute.Reference, error) {
	refs, err := targetReferences(ctx, q, "node", id)
	if err != nil {
		return nil, err
	}
	rows, err := q.QueryContext(ctx, `SELECT id, name FROM outbound_selectors WHERE node_id = ? OR EXISTS
		(SELECT 1 FROM json_each(policy_json, '$.candidates') c WHERE json_extract(c.value, '$.nodeId') = ?)`, id, id)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		ref := contractroute.Reference{Kind: "selector"}
		if err := rows.Scan(&ref.ID, &ref.Name); err != nil {
			_ = rows.Close()
			return nil, err
		}
		refs = append(refs, ref)
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return nil, err
	}
	rows, err = q.QueryContext(ctx, `SELECT key FROM metadata WHERE key IN ('selected_tcp_node_v2', 'selected_udp_node_v2') AND value = ?`, id)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			_ = rows.Close()
			return nil, err
		}
		refs = append(refs, contractroute.Reference{Kind: "default", ID: key, Name: "Default " + strings.TrimSuffix(strings.TrimPrefix(key, "selected_"), "_node_v2") + " destination"})
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return nil, err
	}
	rows, err = q.QueryContext(ctx, `SELECT data_json FROM nodes_v2 WHERE id <> ?`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		var node contractnode.Node
		if err := json.Unmarshal([]byte(value), &node); err != nil {
			return nil, err
		}
		if nodeUses(node.Chain, id) {
			refs = append(refs, contractroute.Reference{Kind: "node", ID: node.ID, Name: node.Name})
		}
	}
	return refs, rows.Err()
}

func nodeUses(chain []contractnode.Protocol, id string) bool {
	for _, p := range chain {
		if p.Set != nil {
			if slices.Contains(p.Set.Nodes, id) {
				return true
			}
		}
		if p.PointAsEndpoint != nil && p.PointAsEndpoint.Hash == id {
			return true
		}
		if p.NetworkSplit != nil {
			if p.NetworkSplit.TCP != nil && nodeUses([]contractnode.Protocol{*p.NetworkSplit.TCP}, id) {
				return true
			}
			if p.NetworkSplit.UDP != nil && nodeUses([]contractnode.Protocol{*p.NetworkSplit.UDP}, id) {
				return true
			}
		}
	}
	return false
}
