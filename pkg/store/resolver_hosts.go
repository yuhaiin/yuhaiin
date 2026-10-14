package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"

	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
)

func (s *ResolverConfigStore) ListHostEntries(ctx context.Context, page, pageSize int, query string) ([]contractresolver.HostEntry, int, error) {
	if s == nil || s.db == nil {
		return nil, 0, errors.New("resolver config store database is nil")
	}
	page = max(1, page)
	if pageSize <= 0 {
		pageSize = 25
	}
	pageSize = min(100, pageSize)
	query = strings.ToLower(strings.TrimSpace(query))
	where := ""
	args := []any{}
	if query != "" {
		where = " WHERE instr(lower(host), ?) > 0 OR instr(lower(target), ?) > 0"
		args = append(args, query, query)
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = tx.Rollback() }()
	var total int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM dns_hosts"+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	items := []contractresolver.HostEntry{}
	if page-1 > math.MaxInt/pageSize {
		return items, total, nil
	}
	queryArgs := append(slices.Clone(args), pageSize, (page-1)*pageSize)
	// The host primary key supplies directory order without sorting all rows.
	rows, err := tx.QueryContext(ctx, "SELECT host, target FROM dns_hosts"+where+" ORDER BY host LIMIT ? OFFSET ?", queryArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var item contractresolver.HostEntry
		if err := rows.Scan(&item.Host, &item.Target); err != nil {
			return nil, 0, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (s *ResolverConfigStore) HostEntry(ctx context.Context, host string) (contractresolver.HostEntry, error) {
	if s == nil || s.db == nil {
		return contractresolver.HostEntry{}, errors.New("resolver config store database is nil")
	}
	item := contractresolver.HostEntry{Host: host}
	err := s.db.QueryRowContext(ctx, "SELECT target FROM dns_hosts WHERE host = ?", host).Scan(&item.Target)
	if errors.Is(err, sql.ErrNoRows) {
		return item, fmt.Errorf("%w: host %s", ErrNotFound, host)
	}
	return item, err
}

func (s *ResolverConfigStore) SaveHostEntry(ctx context.Context, item contractresolver.HostEntry, create bool) (contractresolver.HostEntry, error) {
	if s == nil || s.db == nil {
		return item, errors.New("resolver config store database is nil")
	}
	if err := item.Validate(); err != nil {
		return item, err
	}
	var result sql.Result
	var err error
	if create {
		result, err = s.db.ExecContext(ctx, "INSERT INTO dns_hosts(host, target) VALUES (?, ?) ON CONFLICT(host) DO NOTHING", item.Host, item.Target)
	} else {
		result, err = s.db.ExecContext(ctx, "UPDATE dns_hosts SET target = ? WHERE host = ?", item.Target, item.Host)
	}
	if err != nil {
		return item, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return item, err
	}
	if count == 0 {
		if create {
			return item, fmt.Errorf("%w: host %s already exists", ErrConflict, item.Host)
		}
		return item, fmt.Errorf("%w: host %s", ErrNotFound, item.Host)
	}
	return item, nil
}

func (s *ResolverConfigStore) DeleteHostEntry(ctx context.Context, host string) error {
	if s == nil || s.db == nil {
		return errors.New("resolver config store database is nil")
	}
	result, err := s.db.ExecContext(ctx, "DELETE FROM dns_hosts WHERE host = ?", host)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return fmt.Errorf("%w: host %s", ErrNotFound, host)
	}
	return nil
}
