package store

import (
	"context"
	"database/sql"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"uuid"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/log"
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

func (s *NodeStore) Selector(ctx context.Context, id string) (contractnode.Selector, error) {
	return NewSelectorStore(s.db).Get(ctx, id)
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
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := SaveNodeContract(ctx, tx, node, updatedAt); err != nil {
		return err
	}
	if err := validateNodeDependencies(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
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
	rows, err := tx.QueryContext(ctx, `SELECT id, name FROM nodes_v2 WHERE group_name = ? AND origin = 'remote'`, group)
	if err != nil {
		return err
	}
	oldIDs := []string{}
	byName := map[string][]string{}
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			_ = rows.Close()
			return err
		}
		oldIDs = append(oldIDs, id)
		byName[name] = append(byName[name], id)
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, node := range nodes {
		node.Group, node.Origin = group, "remote"
		if node.ID == "" {
			if candidates := byName[node.Name]; len(candidates) == 1 && !seen[candidates[0]] {
				node.ID = candidates[0]
			} else {
				node.ID = uuid.New().String()
			}
		}
		if seen[node.ID] {
			return fmt.Errorf("subscription contains duplicate node ID %q", node.ID)
		}
		seen[node.ID] = true
		var existingOrigin, existingGroup string
		err := tx.QueryRowContext(ctx, `SELECT origin, group_name FROM nodes_v2 WHERE id = ?`, node.ID).Scan(&existingOrigin, &existingGroup)
		if err == nil && (existingOrigin != "remote" || existingGroup != group) {
			return fmt.Errorf("node ID %q belongs to another source", node.ID)
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err := SaveNodeContract(ctx, tx, node, updatedAt); err != nil {
			return err
		}
	}
	for _, id := range oldIDs {
		if seen[id] {
			continue
		}
		refs, err := NodeReferences(ctx, tx, id)
		if err != nil {
			return err
		}
		if len(refs) > 0 {
			return &ResourceInUseError{References: refs}
		}
		if err := DeleteNodeContract(ctx, tx, id); err != nil {
			return err
		}
	}
	if err := validateNodeDependencies(ctx, tx); err != nil {
		return err
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

func (s *NodeStore) List(ctx context.Context) ([]contractnode.Node, error) { return s.list(ctx, false) }

func (s *NodeStore) list(ctx context.Context, strict bool) ([]contractnode.Node, error) {
	var items []contractnode.Node
	err := s.walk(ctx, strict, func(item contractnode.Node) error { items = append(items, item); return nil })
	return items, err
}

// RangeForRecovery streams resources through the existing decoder, aborting
// instead of silently omitting malformed persisted records.
func (s *NodeStore) RangeForRecovery(ctx context.Context, visit func(contractnode.Node) error) error {
	return s.walk(ctx, true, visit)
}

func (s *NodeStore) walk(ctx context.Context, strict bool, visit func(contractnode.Node) error) error {
	if s == nil || s.db == nil {
		return errors.New("node store database is nil")
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, data_json
		FROM nodes_v2
		ORDER BY group_name, name, id
	`)
	if err != nil {
		return fmt.Errorf("query node contracts failed: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var id, dataJSON string
		if err := rows.Scan(&id, &dataJSON); err != nil {
			return fmt.Errorf("scan node contract failed: %w", err)
		}
		node, err := decodeNodeContract(dataJSON)
		if strict && err == nil && node.ID != id {
			err = errors.New("node identity differs from storage key")
		}
		if err != nil {
			if strict {
				return fmt.Errorf("stored node %s cannot be inventoried for recovery", id)
			}
			log.Warn("skip invalid stored node", "id", id, "err", err)
			continue
		}
		if err := visit(node); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate node contracts failed: %w", err)
	}
	return nil
}

// NodeGroupSummary contains only group metadata, never full node contracts.
type NodeGroupSummary struct {
	Name    string `json:"name"`
	Count   int    `json:"count"`
	Enabled int    `json:"enabled"`
}

func (s *NodeStore) Groups(ctx context.Context) ([]NodeGroupSummary, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("node store database is nil")
	}
	rows, err := s.db.QueryContext(ctx, `
        SELECT COALESCE(NULLIF(group_name,''), 'manual'), COUNT(*),
               SUM(CASE WHEN enabled != 0 THEN 1 ELSE 0 END)
        FROM nodes_v2
        GROUP BY COALESCE(NULLIF(group_name,''), 'manual')
        ORDER BY 1
    `)
	if err != nil {
		return nil, fmt.Errorf("list node groups: %w", err)
	}
	defer rows.Close()
	result := []NodeGroupSummary{}
	for rows.Next() {
		var item NodeGroupSummary
		if err := rows.Scan(&item.Name, &item.Count, &item.Enabled); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

// ListPage reads only the requested page. In particular, selecting one
// default node must not deserialize every node stored in other groups.
func (s *NodeStore) ListPage(ctx context.Context, group, query string, enabledOnly bool, page, pageSize int) ([]contractnode.Node, int, error) {
	if s == nil || s.db == nil {
		return nil, 0, errors.New("node store database is nil")
	}
	group = strings.TrimSpace(group)
	page = max(1, page)
	if pageSize <= 0 {
		pageSize = 100
	}
	pageSize = min(100, pageSize)
	where := "1 = 1"
	args := []any{}
	if group != "" {
		where = "(group_name = ? OR (group_name = '' AND ? = 'manual'))"
		args = append(args, group, group)
	}
	if enabledOnly {
		where += " AND enabled != 0"
	}
	if query = strings.TrimSpace(query); query != "" {
		where += " AND (LOWER(id) LIKE ? OR LOWER(name) LIKE ? OR LOWER(group_name) LIKE ? OR LOWER(origin) LIKE ? OR LOWER(chain_types_json) LIKE ?)"
		needle := "%" + strings.ToLower(query) + "%"
		for range 5 {
			args = append(args, needle)
		}
	}
	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM nodes_v2 WHERE "+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count group nodes: %w", err)
	}
	queryArgs := append(slices.Clone(args), pageSize, (page-1)*pageSize)
	rows, err := s.db.QueryContext(ctx, "SELECT id, data_json FROM nodes_v2 WHERE "+where+" ORDER BY name, id LIMIT ? OFFSET ?", queryArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("list group nodes: %w", err)
	}
	defer rows.Close()
	items := []contractnode.Node{}
	for rows.Next() {
		var id, raw string
		if err := rows.Scan(&id, &raw); err != nil {
			return nil, 0, err
		}
		node, err := decodeNodeContract(raw)
		if err != nil {
			log.Warn("skip invalid stored node", "id", id, "err", err)
			continue
		}
		items = append(items, node)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return items, total, nil
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
	refs, err := NodeReferences(ctx, tx, id)
	if err != nil {
		return err
	}
	if len(refs) > 0 {
		return &ResourceInUseError{References: refs}
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
	return s.Select(ctx, contractnode.SelectionRequest{TCPID: id, UDPID: id})
}

func (s *NodeStore) Select(ctx context.Context, selection contractnode.SelectionRequest) error {
	if s == nil || s.db == nil {
		return errors.New("node store database is nil")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for key, value := range map[string]string{
		selectedTCPNodeMetadataKey: selection.TCPID,
		selectedUDPNodeMetadataKey: selection.UDPID,
	} {
		node, err := getNodeContract(ctx, tx, value)
		if err != nil {
			return err
		}
		if !node.Enabled {
			return fmt.Errorf("disabled node %q cannot be used as the default destination", node.Name)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO metadata(key, value)
			VALUES (?, ?)
			ON CONFLICT(key) DO UPDATE SET value = excluded.value
		`, key, value); err != nil {
			return fmt.Errorf("update metadata %q failed: %w", key, err)
		}
	}
	return tx.Commit()
}

// Selection reads both default destinations from one database snapshot.
func (s *NodeStore) Selection(ctx context.Context) (contractnode.Selection, error) {
	if s == nil || s.db == nil {
		return contractnode.Selection{}, errors.New("node store database is nil")
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return contractnode.Selection{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var selection contractnode.Selection
	for key, destination := range map[string]**contractnode.Node{
		selectedTCPNodeMetadataKey: &selection.TCP,
		selectedUDPNodeMetadataKey: &selection.UDP,
	} {
		var id string
		err := tx.QueryRowContext(ctx, `SELECT value FROM metadata WHERE key = ?`, key).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) || id == "" {
			continue
		}
		if err != nil {
			return selection, err
		}
		node, err := getNodeContract(ctx, tx, id)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return selection, err
		}
		*destination = &node
	}
	return selection, tx.Commit()
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
		SELECT node_id FROM outbound_selectors
		UNION
		SELECT json_extract(c.value, '$.nodeId') FROM outbound_selectors, json_each(policy_json, '$.candidates') c
		UNION
		SELECT json_extract(data_json, '$.target.id') FROM route_rules_v2 WHERE json_extract(data_json, '$.target.type') = 'node'
		UNION
		SELECT json_extract(default_target_json, '$.id') FROM route_settings WHERE json_extract(default_target_json, '$.type') = 'node'
		UNION
		SELECT json_extract(r.value, '$.target.id') FROM route_configuration_state s, json_each(s.applied_rules_json) r WHERE json_extract(r.value, '$.target.type') = 'node'
		UNION
		SELECT json_extract(applied_config_json, '$.defaultTarget.id') FROM route_configuration_state WHERE json_extract(applied_config_json, '$.defaultTarget.type') = 'node'
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
	configured, err := s.List(ctx)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]contractnode.Node, len(configured))
	for _, node := range configured {
		byID[node.ID] = node
	}
	var includeChain func([]contractnode.Protocol)
	var includeNode func(string)
	visited := map[string]bool{}
	includeNode = func(id string) {
		if id == "" {
			return
		}
		if visited[id] {
			return
		}
		visited[id] = true
		ids[id] = struct{}{}
		if node, exists := byID[id]; exists {
			includeChain(node.Chain)
		}
	}
	includeChain = func(chain []contractnode.Protocol) {
		for _, protocol := range chain {
			if protocol.Set != nil {
				for _, id := range protocol.Set.Nodes {
					includeNode(id)
				}
			}
			if protocol.PointAsEndpoint != nil {
				includeNode(protocol.PointAsEndpoint.Hash)
			}
			if protocol.NetworkSplit != nil {
				if protocol.NetworkSplit.TCP != nil {
					includeChain([]contractnode.Protocol{*protocol.NetworkSplit.TCP})
				}
				if protocol.NetworkSplit.UDP != nil {
					includeChain([]contractnode.Protocol{*protocol.NetworkSplit.UDP})
				}
			}
		}
	}
	for id := range ids {
		includeNode(id)
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
