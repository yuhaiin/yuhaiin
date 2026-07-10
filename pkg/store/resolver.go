package store

import (
	"context"
	"database/sql"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"strings"
	"time"

	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
)

type ResolverStore struct {
	db *sql.DB
}

type ResolverExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func NewResolverStore(db *sql.DB) *ResolverStore {
	return &ResolverStore{db: db}
}

func (s *ResolverStore) List(ctx context.Context) ([]contractresolver.Resolver, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("resolver store database is nil")
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT data_json
		FROM resolvers_v2
		ORDER BY id
	`)
	if err != nil {
		return nil, fmt.Errorf("query resolver contracts failed: %w", err)
	}
	defer rows.Close()

	var out []contractresolver.Resolver
	for rows.Next() {
		var dataJSON string
		if err := rows.Scan(&dataJSON); err != nil {
			return nil, fmt.Errorf("scan resolver contract failed: %w", err)
		}
		resolver, err := decodeResolver(dataJSON)
		if err != nil {
			return nil, err
		}
		out = append(out, resolver)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate resolver contracts failed: %w", err)
	}
	return out, nil
}

func (s *ResolverStore) Get(ctx context.Context, id string) (contractresolver.Resolver, error) {
	if s == nil || s.db == nil {
		return contractresolver.Resolver{}, errors.New("resolver store database is nil")
	}
	var dataJSON string
	err := s.db.QueryRowContext(ctx, `SELECT data_json FROM resolvers_v2 WHERE id = ?`, id).Scan(&dataJSON)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return contractresolver.Resolver{}, fmt.Errorf("%w: resolver %s not found", ErrNotFound, id)
	case err != nil:
		return contractresolver.Resolver{}, fmt.Errorf("query resolver %q failed: %w", id, err)
	}
	return decodeResolver(dataJSON)
}

func (s *ResolverStore) Save(ctx context.Context, resolver contractresolver.Resolver, updatedAt int64) error {
	if s == nil || s.db == nil {
		return errors.New("resolver store database is nil")
	}
	return SaveResolverContract(ctx, s.db, resolver, updatedAt)
}

func SaveResolverContract(ctx context.Context, execer ResolverExecer, resolver contractresolver.Resolver, updatedAt int64) error {
	resolver = normalizeResolver(resolver)
	if err := resolver.Validate(); err != nil {
		return err
	}
	if updatedAt == 0 {
		updatedAt = time.Now().Unix()
	}
	dataJSON, err := json.Marshal(resolver)
	if err != nil {
		return fmt.Errorf("encode resolver %q failed: %w", resolver.ID, err)
	}
	if _, err := execer.ExecContext(ctx, `
		INSERT INTO resolvers_v2(id, resolver_type, host, updated_at, data_json)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			resolver_type = excluded.resolver_type,
			host = excluded.host,
			updated_at = excluded.updated_at,
			data_json = excluded.data_json
	`, resolver.ID, resolver.Type, resolver.Host, updatedAt, string(dataJSON)); err != nil {
		return fmt.Errorf("upsert resolver %q failed: %w", resolver.ID, err)
	}
	return nil
}

func (s *ResolverStore) Delete(ctx context.Context, id string) error {
	if s == nil || s.db == nil {
		return errors.New("resolver store database is nil")
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM resolvers_v2 WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete resolver %q failed: %w", id, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: resolver %s not found", ErrNotFound, id)
	}
	return nil
}

func decodeResolver(dataJSON string) (contractresolver.Resolver, error) {
	var resolver contractresolver.Resolver
	if err := json.Unmarshal([]byte(dataJSON), &resolver); err != nil {
		return contractresolver.Resolver{}, fmt.Errorf("decode resolver contract failed: %w", err)
	}
	resolver = normalizeResolver(resolver)
	if err := resolver.Validate(); err != nil {
		return contractresolver.Resolver{}, err
	}
	return resolver, nil
}

func normalizeResolver(resolver contractresolver.Resolver) contractresolver.Resolver {
	resolver.ID = strings.TrimSpace(resolver.ID)
	if strings.TrimSpace(resolver.Type) == "" {
		resolver.Type = "udp"
	}
	if resolver.Type == "system" {
		resolver.System = true
		if strings.TrimSpace(resolver.Host) == "" {
			resolver.Host = "system default"
		}
	}
	return resolver
}
