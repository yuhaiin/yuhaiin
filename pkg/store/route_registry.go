package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
)

const (
	DefaultRouteRegistryID   = "kitte"
	DefaultRouteRegistryName = "Kitte"
	DefaultRouteRegistryURL  = "https://raw.githubusercontent.com/yuhaiin/kitte/auto-update/manifest.json"
)

type RouteRegistryStore struct {
	db *sql.DB
}

func NewRouteRegistryStore(db *sql.DB) *RouteRegistryStore {
	return &RouteRegistryStore{db: db}
}

func (s *RouteRegistryStore) ListRegistries(ctx context.Context) (contractroute.RegistryList, error) {
	if s == nil || s.db == nil {
		return contractroute.RegistryList{}, errors.New("route registry store database is nil")
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, url, enabled, builtin, updated_at
		FROM route_registries
		ORDER BY builtin DESC, name COLLATE NOCASE, id
	`)
	if err != nil {
		return contractroute.RegistryList{}, fmt.Errorf("query route registries failed: %w", err)
	}
	defer rows.Close()

	var out contractroute.RegistryList
	for rows.Next() {
		var item contractroute.Registry
		var enabled, builtin int
		var updatedAt int64
		if err := rows.Scan(&item.ID, &item.Name, &item.URL, &enabled, &builtin, &updatedAt); err != nil {
			return contractroute.RegistryList{}, fmt.Errorf("scan route registry failed: %w", err)
		}
		item.Enabled = enabled != 0
		item.Builtin = builtin != 0
		item.UpdatedAt = fmt.Sprint(updatedAt)
		out.Items = append(out.Items, item)
	}
	if err := rows.Err(); err != nil {
		return contractroute.RegistryList{}, fmt.Errorf("iterate route registries failed: %w", err)
	}
	return out, nil
}

func (s *RouteRegistryStore) GetRegistry(ctx context.Context, id string) (contractroute.Registry, error) {
	if s == nil || s.db == nil {
		return contractroute.Registry{}, errors.New("route registry store database is nil")
	}

	var item contractroute.Registry
	var enabled, builtin int
	var updatedAt int64
	err := s.db.QueryRowContext(ctx, `
		SELECT id, name, url, enabled, builtin, updated_at
		FROM route_registries
		WHERE id = ?
	`, strings.TrimSpace(id)).Scan(&item.ID, &item.Name, &item.URL, &enabled, &builtin, &updatedAt)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return contractroute.Registry{}, fmt.Errorf("%w: route registry %s not found", ErrNotFound, id)
	case err != nil:
		return contractroute.Registry{}, fmt.Errorf("query route registry %q failed: %w", id, err)
	}
	item.Enabled = enabled != 0
	item.Builtin = builtin != 0
	item.UpdatedAt = fmt.Sprint(updatedAt)
	return item, nil
}

func (s *RouteRegistryStore) SaveRegistry(ctx context.Context, item contractroute.Registry, updatedAt int64) (contractroute.Registry, error) {
	if s == nil || s.db == nil {
		return contractroute.Registry{}, errors.New("route registry store database is nil")
	}

	item = normalizeRegistry(item)
	if err := validateRegistry(item); err != nil {
		return contractroute.Registry{}, err
	}
	if updatedAt == 0 {
		updatedAt = time.Now().Unix()
	}

	if item.ID == DefaultRouteRegistryID {
		item.Name = DefaultRouteRegistryName
		item.URL = DefaultRouteRegistryURL
		item.Builtin = true
	} else {
		item.Builtin = false
	}

	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO route_registries(id, name, url, enabled, builtin, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name = excluded.name,
			url = excluded.url,
			enabled = excluded.enabled,
			builtin = CASE WHEN route_registries.builtin = 1 THEN 1 ELSE excluded.builtin END,
			updated_at = excluded.updated_at
	`, item.ID, item.Name, item.URL, boolInt(item.Enabled), boolInt(item.Builtin), updatedAt); err != nil {
		return contractroute.Registry{}, fmt.Errorf("upsert route registry %q failed: %w", item.ID, err)
	}

	return s.GetRegistry(ctx, item.ID)
}

func (s *RouteRegistryStore) DeleteRegistry(ctx context.Context, id string) error {
	if s == nil || s.db == nil {
		return errors.New("route registry store database is nil")
	}

	item, err := s.GetRegistry(ctx, id)
	if err != nil {
		return err
	}
	if item.Builtin {
		return fmt.Errorf("built-in route registry %q cannot be deleted", item.ID)
	}

	res, err := s.db.ExecContext(ctx, `DELETE FROM route_registries WHERE id = ?`, item.ID)
	if err != nil {
		return fmt.Errorf("delete route registry %q failed: %w", item.ID, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: route registry %s not found", ErrNotFound, item.ID)
	}
	return nil
}

func normalizeRegistry(item contractroute.Registry) contractroute.Registry {
	item.ID = strings.TrimSpace(item.ID)
	item.Name = strings.TrimSpace(item.Name)
	item.URL = strings.TrimSpace(item.URL)

	if item.ID == "" && item.URL != "" {
		sum := sha256.Sum256([]byte(item.URL))
		item.ID = "registry-" + hex.EncodeToString(sum[:6])
	}
	if item.Name == "" {
		if u, err := url.Parse(item.URL); err == nil {
			item.Name = u.Hostname()
		}
	}
	return item
}

func validateRegistry(item contractroute.Registry) error {
	if item.ID == "" {
		return errors.New("route registry id is empty")
	}
	if item.Name == "" {
		return errors.New("route registry name is empty")
	}
	u, err := url.Parse(item.URL)
	if err != nil {
		return fmt.Errorf("parse route registry url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("route registry url must use http or https")
	}
	if u.Host == "" {
		return errors.New("route registry url host is empty")
	}
	return nil
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
