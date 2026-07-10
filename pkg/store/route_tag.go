package store

import (
	"context"
	"database/sql"
	json "encoding/json/v2"
	"errors"
	"fmt"
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

func NewRouteTagStore(db *sql.DB) *RouteTagStore {
	return &RouteTagStore{db: db}
}

func (s *RouteTagStore) ListTags(ctx context.Context) ([]contractroute.TagItem, error) {
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
	defer rows.Close()

	var out []contractroute.TagItem
	for rows.Next() {
		var name, dataJSON string
		if err := rows.Scan(&name, &dataJSON); err != nil {
			return nil, fmt.Errorf("scan tag contract failed: %w", err)
		}
		tag, err := decodeRouteTag(name, dataJSON)
		if err != nil {
			return nil, err
		}
		out = append(out, tag)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tag contracts failed: %w", err)
	}
	return out, nil
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
	res, err := s.db.ExecContext(ctx, `DELETE FROM node_tags_v2 WHERE name = ?`, name)
	if err != nil {
		return fmt.Errorf("delete tag %q failed: %w", name, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: tag %s not found", ErrNotFound, name)
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
