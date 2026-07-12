package store

import (
	"context"
	"database/sql"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"time"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/utils/id"
)

type NodeStore struct {
	db *sql.DB
}

const (
	selectedTCPNodeMetadataKey = "selected_tcp_node_v2"
	selectedUDPNodeMetadataKey = "selected_udp_node_v2"
)

func NewNodeStore(db *sql.DB) *NodeStore {
	return &NodeStore{db: db}
}

type NodeExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

type NodeQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s *NodeStore) Save(ctx context.Context, node contractnode.Node, updatedAt int64) error {
	if s == nil || s.db == nil {
		return errors.New("node store database is nil")
	}
	return SaveNodeContract(ctx, s.db, node, updatedAt)
}

func (s *NodeStore) ReplaceRemote(ctx context.Context, group string, nodes []contractnode.Node, updatedAt int64) error {
	if s == nil || s.db == nil {
		return errors.New("node store database is nil")
	}
	if updatedAt == 0 {
		updatedAt = time.Now().Unix()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin remote node replace transaction failed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := DeleteRemoteNodeContracts(ctx, tx, group); err != nil {
		return err
	}
	for _, node := range nodes {
		node.Group = group
		node.Origin = "remote"
		if node.ID == "" {
			node.ID = id.GenerateUUID().String()
		}
		if err := SaveNodeContract(ctx, tx, node, updatedAt); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit remote node replace transaction failed: %w", err)
	}
	return nil
}

func SaveNodeContract(ctx context.Context, execer NodeExecer, node contractnode.Node, updatedAt int64) error {
	if err := node.Validate(); err != nil {
		return err
	}
	if updatedAt == 0 {
		updatedAt = time.Now().Unix()
	}
	dataJSON, err := json.Marshal(node)
	if err != nil {
		return fmt.Errorf("encode node contract %q failed: %w", node.ID, err)
	}
	chainTypes, err := json.Marshal(chainTypes(node.Chain))
	if err != nil {
		return fmt.Errorf("encode node chain types %q failed: %w", node.ID, err)
	}
	if _, err := execer.ExecContext(ctx, `
		INSERT INTO nodes_v2(id, name, group_name, origin, enabled, chain_types_json, updated_at, data_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name = excluded.name,
			group_name = excluded.group_name,
			origin = excluded.origin,
			enabled = excluded.enabled,
			chain_types_json = excluded.chain_types_json,
			updated_at = excluded.updated_at,
			data_json = excluded.data_json
	`, node.ID, node.Name, node.Group, node.Origin, boolToInt(node.Enabled), string(chainTypes), updatedAt, string(dataJSON)); err != nil {
		return fmt.Errorf("upsert node contract %q failed: %w", node.ID, err)
	}
	return nil
}

func (s *NodeStore) Get(ctx context.Context, id string) (contractnode.Node, error) {
	if s == nil || s.db == nil {
		return contractnode.Node{}, errors.New("node store database is nil")
	}
	return getNodeContract(ctx, s.db, id)
}

func (s *NodeStore) List(ctx context.Context) ([]contractnode.Node, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("node store database is nil")
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT data_json
		FROM nodes_v2
		ORDER BY group_name, name, id
	`)
	if err != nil {
		return nil, fmt.Errorf("query node contracts failed: %w", err)
	}
	defer rows.Close()

	var nodes []contractnode.Node
	for rows.Next() {
		var dataJSON string
		if err := rows.Scan(&dataJSON); err != nil {
			return nil, fmt.Errorf("scan node contract failed: %w", err)
		}
		node, err := decodeNodeContract(dataJSON)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, node)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate node contracts failed: %w", err)
	}
	return nodes, nil
}

func (s *NodeStore) Delete(ctx context.Context, id string) error {
	if s == nil || s.db == nil {
		return errors.New("node store database is nil")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin node delete transaction failed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM node_tags WHERE target_kind = 'node' AND target_id = ?`, id); err != nil {
		return fmt.Errorf("delete node tag members for %q failed: %w", id, err)
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM nodes_v2 WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete node contract %q failed: %w", id, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: node %s not found", ErrNotFound, id)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit node delete transaction failed: %w", err)
	}
	return nil
}

func (s *NodeStore) Selected(ctx context.Context, tcp bool) (contractnode.Node, bool, error) {
	if s == nil || s.db == nil {
		return contractnode.Node{}, false, errors.New("node store database is nil")
	}
	key := selectedUDPNodeMetadataKey
	if tcp {
		key = selectedTCPNodeMetadataKey
	}
	var id string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM metadata WHERE key = ?`, key).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) || id == "" {
		return contractnode.Node{}, false, nil
	}
	if err != nil {
		return contractnode.Node{}, false, fmt.Errorf("load metadata %q failed: %w", key, err)
	}
	node, err := s.Get(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return contractnode.Node{}, false, nil
	}
	return node, err == nil, err
}

func (s *NodeStore) Use(ctx context.Context, id string) error {
	if _, err := s.Get(ctx, id); err != nil {
		return err
	}
	if s == nil || s.db == nil {
		return errors.New("node store database is nil")
	}
	for key, value := range map[string]string{
		selectedTCPNodeMetadataKey: id,
		selectedUDPNodeMetadataKey: id,
	} {
		if _, err := s.db.ExecContext(ctx, `
			INSERT INTO metadata(key, value)
			VALUES (?, ?)
			ON CONFLICT(key) DO UPDATE SET value = excluded.value
		`, key, value); err != nil {
			return fmt.Errorf("update metadata %q failed: %w", key, err)
		}
	}
	return nil
}

func (s *NodeStore) AddTag(ctx context.Context, tag, kind, target string) error {
	if s == nil || s.db == nil {
		return errors.New("node store database is nil")
	}
	if kind == "" {
		kind = "node"
	}
	if kind != "node" && kind != "tag" {
		return fmt.Errorf("unknown node tag target kind %q", kind)
	}
	if tag == target && kind == "tag" {
		return nil
	}
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO node_tags(tag_name, target_kind, target_id, updated_at)
		VALUES (?, ?, ?, unixepoch())
		ON CONFLICT(tag_name, target_kind, target_id) DO UPDATE SET updated_at = excluded.updated_at
	`, tag, kind, target); err != nil {
		return fmt.Errorf("insert node tag failed: %w", err)
	}
	return nil
}

func (s *NodeStore) DeleteTag(ctx context.Context, tag string) error {
	if s == nil || s.db == nil {
		return errors.New("node store database is nil")
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM node_tags WHERE tag_name = ?`, tag); err != nil {
		return fmt.Errorf("delete node tag %q failed: %w", tag, err)
	}
	return nil
}

type NodeTag struct {
	Name      string
	Kind      string
	TargetIDs []string
}

func (s *NodeStore) GetTag(ctx context.Context, name string) (NodeTag, bool, error) {
	if s == nil || s.db == nil {
		return NodeTag{}, false, errors.New("node store database is nil")
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT target_kind, target_id
		FROM node_tags
		WHERE tag_name = ?
		ORDER BY target_kind, target_id
	`, name)
	if err != nil {
		return NodeTag{}, false, fmt.Errorf("query node tag %q failed: %w", name, err)
	}
	defer rows.Close()
	tag := NodeTag{Name: name, Kind: "node"}
	for rows.Next() {
		var kind, targetID string
		if err := rows.Scan(&kind, &targetID); err != nil {
			return NodeTag{}, false, fmt.Errorf("scan node tag %q failed: %w", name, err)
		}
		if kind == "tag" {
			tag.Kind = "mirror"
		}
		tag.TargetIDs = append(tag.TargetIDs, targetID)
	}
	if err := rows.Err(); err != nil {
		return NodeTag{}, false, fmt.Errorf("iterate node tag %q failed: %w", name, err)
	}
	return tag, len(tag.TargetIDs) > 0, nil
}

func (s *NodeStore) UsingIDs(ctx context.Context) ([]string, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("node store database is nil")
	}
	ids := map[string]struct{}{}
	rows, err := s.db.QueryContext(ctx, `
		SELECT value
		FROM metadata
		WHERE key IN ('selected_tcp_node_v2', 'selected_udp_node_v2')
		UNION
		SELECT target_id
		FROM node_tags
		WHERE target_kind = 'node'
	`)
	if err != nil {
		return nil, fmt.Errorf("query using node ids failed: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan using node id failed: %w", err)
		}
		if id != "" {
			ids[id] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate using node ids failed: %w", err)
	}
	out := make([]string, 0, len(ids))
	for id := range ids {
		out = append(out, id)
	}
	slices.Sort(out)
	return out, nil
}

func DeleteNodeContract(ctx context.Context, execer NodeExecer, id string) error {
	if _, err := execer.ExecContext(ctx, `DELETE FROM nodes_v2 WHERE id = ?`, id); err != nil {
		return fmt.Errorf("delete node contract %q failed: %w", id, err)
	}
	return nil
}

func DeleteRemoteNodeContracts(ctx context.Context, execer NodeExecer, group string) error {
	if _, err := execer.ExecContext(ctx, `DELETE FROM nodes_v2 WHERE group_name = ? AND origin = 'remote'`, group); err != nil {
		return fmt.Errorf("delete remote node contracts for group %q failed: %w", group, err)
	}
	return nil
}

func getNodeContract(ctx context.Context, queryer NodeQueryer, id string) (contractnode.Node, error) {
	var dataJSON string
	err := queryer.QueryRowContext(ctx, `SELECT data_json FROM nodes_v2 WHERE id = ?`, id).Scan(&dataJSON)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return contractnode.Node{}, fmt.Errorf("%w: node %s not found", ErrNotFound, id)
	case err != nil:
		return contractnode.Node{}, fmt.Errorf("query node contract %q failed: %w", id, err)
	}
	return decodeNodeContract(dataJSON)
}

func decodeNodeContract(dataJSON string) (contractnode.Node, error) {
	var node contractnode.Node
	if err := json.Unmarshal([]byte(dataJSON), &node); err != nil {
		return contractnode.Node{}, fmt.Errorf("decode node contract failed: %w", err)
	}
	if err := node.Validate(); err != nil {
		return contractnode.Node{}, err
	}
	return node, nil
}

func chainTypes(chain []contractnode.Protocol) []string {
	out := make([]string, 0, len(chain))
	for _, protocol := range chain {
		out = append(out, protocol.Type)
	}
	return out
}
