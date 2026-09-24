package store

import (
	"context"
	"database/sql"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
)

type RouteTagStore struct {
	db *sql.DB
}

type RouteTagExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

type RouteTagQueryExecer interface {
	RouteTagExecer
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func NewRouteTagStore(db *sql.DB) *RouteTagStore {
	return &RouteTagStore{db: db}
}

// GetTag is the canonical runtime lookup for a tag. The v2 contract table is
// authoritative; the legacy membership table is only used as a migration
// fallback for databases that have not produced a v2 row yet.
func (s *RouteTagStore) GetTag(ctx context.Context, name string) (contractroute.TagItem, bool, error) {
	if s == nil || s.db == nil {
		return contractroute.TagItem{}, false, errors.New("route tag store database is nil")
	}
	return loadRouteTagContract(ctx, s.db, name)
}

func loadRouteTagContract(ctx context.Context, db *sql.DB, name string) (contractroute.TagItem, bool, error) {
	var dataJSON string
	err := db.QueryRowContext(ctx, `
		SELECT members_json
		FROM node_tags_v2
		WHERE name = ?
	`, name).Scan(&dataJSON)
	if err == nil {
		tag, err := decodeRouteTag(name, dataJSON)
		return tag, true, err
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return contractroute.TagItem{}, false, fmt.Errorf("query tag contract %q failed: %w", name, err)
	}

	rows, err := db.QueryContext(ctx, `
		SELECT target_kind, target_id
		FROM node_tags
		WHERE tag_name = ?
		ORDER BY target_kind, target_id
	`, name)
	if err != nil {
		return contractroute.TagItem{}, false, fmt.Errorf("query legacy node tag %q failed: %w", name, err)
	}
	defer rows.Close()

	tag := contractroute.TagItem{Name: name, Type: "node"}
	found := false
	for rows.Next() {
		var kind, targetID string
		if err := rows.Scan(&kind, &targetID); err != nil {
			return contractroute.TagItem{}, false, fmt.Errorf("scan legacy node tag %q failed: %w", name, err)
		}
		found = true
		if kind == "tag" {
			tag.Type = "mirror"
		}
		tag.Hash = append(tag.Hash, targetID)
	}
	if err := rows.Err(); err != nil {
		return contractroute.TagItem{}, false, fmt.Errorf("iterate legacy node tag %q failed: %w", name, err)
	}
	return tag, found, nil
}

func (s *RouteTagStore) ListTags(ctx context.Context) ([]contractroute.TagItem, error) {
	// Tags shown in the UI are the union of configured aliases, legacy rows
	// awaiting migration, and names referenced by route rules.
	if s == nil || s.db == nil {
		return nil, errors.New("route tag store database is nil")
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT name, members_json
		FROM node_tags_v2
		ORDER BY name
	`)
	if err != nil {
		return nil, fmt.Errorf("query tag contracts failed: %w", err)
	}

	var out []contractroute.TagItem
	for rows.Next() {
		var name, dataJSON string
		if err := rows.Scan(&name, &dataJSON); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("scan tag contract failed: %w", err)
		}
		tag, err := decodeRouteTag(name, dataJSON)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		out = append(out, tag)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("iterate tag contracts failed: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close tag contracts failed: %w", err)
	}

	seen := make(map[string]struct{}, len(out))
	for _, tag := range out {
		seen[tag.Name] = struct{}{}
	}
	legacyRows, err := s.db.QueryContext(ctx, `
		SELECT tag_name, target_kind, target_id
		FROM node_tags
		ORDER BY tag_name, target_kind, target_id
	`)
	if err != nil {
		return nil, fmt.Errorf("query legacy node tags failed: %w", err)
	}
	legacyTags := make(map[string]contractroute.TagItem)
	for legacyRows.Next() {
		var name, kind, targetID string
		if err := legacyRows.Scan(&name, &kind, &targetID); err != nil {
			_ = legacyRows.Close()
			return nil, fmt.Errorf("scan legacy node tag failed: %w", err)
		}
		if _, ok := seen[name]; ok {
			continue
		}
		tag := legacyTags[name]
		if tag.Name == "" {
			tag = contractroute.TagItem{Name: name, Type: "node"}
		}
		if kind == "tag" {
			tag.Type = "mirror"
		}
		tag.Hash = append(tag.Hash, targetID)
		legacyTags[name] = tag
	}
	if err := legacyRows.Err(); err != nil {
		_ = legacyRows.Close()
		return nil, fmt.Errorf("iterate legacy node tags failed: %w", err)
	}
	if err := legacyRows.Close(); err != nil {
		return nil, fmt.Errorf("close legacy node tags failed: %w", err)
	}
	for _, tag := range legacyTags {
		out = append(out, tag)
		seen[tag.Name] = struct{}{}
	}

	ruleRows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT tag
		FROM route_rules_v2
		WHERE TRIM(tag) <> ''
	`)
	if err != nil {
		return nil, fmt.Errorf("query route rule tags failed: %w", err)
	}
	for ruleRows.Next() {
		var name string
		if err := ruleRows.Scan(&name); err != nil {
			_ = ruleRows.Close()
			return nil, fmt.Errorf("scan route rule tag failed: %w", err)
		}
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, contractroute.TagItem{Name: name, Type: "node"})
	}
	if err := ruleRows.Err(); err != nil {
		_ = ruleRows.Close()
		return nil, fmt.Errorf("iterate route rule tags failed: %w", err)
	}
	if err := ruleRows.Close(); err != nil {
		return nil, fmt.Errorf("close route rule tags failed: %w", err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func deleteRouteTagNodeMember(ctx context.Context, queryExecer RouteTagQueryExecer, nodeID string) error {
	rows, err := queryExecer.QueryContext(ctx, `
		SELECT name, members_json
		FROM node_tags_v2
	`)
	if err != nil {
		return fmt.Errorf("query tag contracts for node %q failed: %w", nodeID, err)
	}
	type update struct {
		name string
		tag  contractroute.TagItem
	}
	var updates []update
	for rows.Next() {
		var name, dataJSON string
		if err := rows.Scan(&name, &dataJSON); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan tag contract for node %q failed: %w", nodeID, err)
		}
		tag, err := decodeRouteTag(name, dataJSON)
		if err != nil {
			_ = rows.Close()
			return err
		}
		if tag.Type != "node" {
			continue
		}
		filtered := tag.Hash[:0]
		removed := false
		for _, targetID := range tag.Hash {
			if targetID == nodeID {
				removed = true
				continue
			}
			filtered = append(filtered, targetID)
		}
		if removed {
			tag.Hash = filtered
			updates = append(updates, update{name: name, tag: tag})
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("iterate tag contracts for node %q failed: %w", nodeID, err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close tag contracts for node %q failed: %w", nodeID, err)
	}
	for _, item := range updates {
		dataJSON, err := json.Marshal(item.tag)
		if err != nil {
			return fmt.Errorf("encode tag %q after node removal failed: %w", item.name, err)
		}
		if _, err := queryExecer.ExecContext(ctx, `
			UPDATE node_tags_v2
			SET members_json = ?, updated_at = ?
			WHERE name = ?
		`, string(dataJSON), time.Now().Unix(), item.name); err != nil {
			return fmt.Errorf("remove node %q from tag %q failed: %w", nodeID, item.name, err)
		}
	}
	return nil
}

func (s *RouteTagStore) SaveTag(ctx context.Context, tag contractroute.TagItem, updatedAt int64) error {
	if s == nil || s.db == nil {
		return errors.New("route tag store database is nil")
	}
	return SaveRouteTagContract(ctx, s.db, tag, updatedAt)
}

func SaveRouteTagContract(ctx context.Context, execer RouteTagExecer, tag contractroute.TagItem, updatedAt int64) error {
	tag = normalizeRouteTag(tag)
	if err := validateRouteTag(tag); err != nil {
		return err
	}
	if updatedAt == 0 {
		updatedAt = time.Now().Unix()
	}
	dataJSON, err := json.Marshal(tag)
	if err != nil {
		return fmt.Errorf("encode tag %q failed: %w", tag.Name, err)
	}
	if _, err := execer.ExecContext(ctx, `
		INSERT INTO node_tags_v2(id, name, members_json, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name = excluded.name,
			members_json = excluded.members_json,
			updated_at = excluded.updated_at
	`, tag.Name, tag.Name, string(dataJSON), updatedAt); err != nil {
		return fmt.Errorf("upsert tag %q failed: %w", tag.Name, err)
	}
	return nil
}

func (s *RouteTagStore) DeleteTag(ctx context.Context, name string) error {
	if s == nil || s.db == nil {
		return errors.New("route tag store database is nil")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tag delete transaction failed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	v2Result, err := tx.ExecContext(ctx, `DELETE FROM node_tags_v2 WHERE name = ?`, name)
	if err != nil {
		return fmt.Errorf("delete tag %q failed: %w", name, err)
	}
	legacyResult, err := tx.ExecContext(ctx, `DELETE FROM node_tags WHERE tag_name = ?`, name)
	if err != nil {
		return fmt.Errorf("delete legacy tag %q failed: %w", name, err)
	}
	v2Count, _ := v2Result.RowsAffected()
	legacyCount, _ := legacyResult.RowsAffected()
	if v2Count == 0 && legacyCount == 0 {
		return fmt.Errorf("%w: tag %s not found", ErrNotFound, name)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tag delete transaction failed: %w", err)
	}
	return nil
}

func decodeRouteTag(name, dataJSON string) (contractroute.TagItem, error) {
	var tag contractroute.TagItem
	if err := json.Unmarshal([]byte(dataJSON), &tag); err != nil {
		return contractroute.TagItem{}, fmt.Errorf("decode tag %q failed: %w", name, err)
	}
	if tag.Name == "" {
		tag.Name = name
	}
	tag = normalizeRouteTag(tag)
	if err := validateRouteTag(tag); err != nil {
		return contractroute.TagItem{}, fmt.Errorf("stored tag %q is invalid: %w", name, err)
	}
	return tag, nil
}

func normalizeRouteTag(tag contractroute.TagItem) contractroute.TagItem {
	tag.Name = strings.TrimSpace(tag.Name)
	if strings.TrimSpace(tag.Type) == "" {
		tag.Type = "node"
	}
	return tag
}

func validateRouteTag(tag contractroute.TagItem) error {
	if strings.TrimSpace(tag.Name) == "" {
		return errors.New("tag name is empty")
	}
	if tag.Type != "node" && tag.Type != "mirror" {
		return fmt.Errorf("unknown tag type %q", tag.Type)
	}
	return nil
}
