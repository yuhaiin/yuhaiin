package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"

	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
)

type ResolverConfigStore struct {
	db *sql.DB
}

func NewResolverConfigStore(db *sql.DB) *ResolverConfigStore {
	return &ResolverConfigStore{db: db}
}

func (s *ResolverConfigStore) Hosts(ctx context.Context) (contractresolver.Hosts, error) {
	if s == nil || s.db == nil {
		return contractresolver.Hosts{}, errors.New("resolver config store database is nil")
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT host, target
		FROM dns_hosts
		ORDER BY host
	`)
	if err != nil {
		return contractresolver.Hosts{}, fmt.Errorf("query dns hosts failed: %w", err)
	}
	defer rows.Close()

	hosts := map[string]string{}
	for rows.Next() {
		var host, target string
		if err := rows.Scan(&host, &target); err != nil {
			return contractresolver.Hosts{}, fmt.Errorf("scan dns host failed: %w", err)
		}
		hosts[host] = target
	}
	if err := rows.Err(); err != nil {
		return contractresolver.Hosts{}, fmt.Errorf("iterate dns hosts failed: %w", err)
	}
	return contractresolver.Hosts{Hosts: hosts}, nil
}

func (s *ResolverConfigStore) SaveHosts(ctx context.Context, hosts contractresolver.Hosts) (contractresolver.Hosts, error) {
	if s == nil || s.db == nil {
		return contractresolver.Hosts{}, errors.New("resolver config store database is nil")
	}
	if hosts.Hosts == nil {
		hosts.Hosts = map[string]string{}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return contractresolver.Hosts{}, fmt.Errorf("begin dns hosts transaction failed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `DELETE FROM dns_hosts`); err != nil {
		return contractresolver.Hosts{}, fmt.Errorf("clear dns hosts failed: %w", err)
	}
	keys := make([]string, 0, len(hosts.Hosts))
	for host := range hosts.Hosts {
		keys = append(keys, host)
	}
	slices.Sort(keys)
	for _, host := range keys {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO dns_hosts(host, target)
			VALUES (?, ?)
		`, host, hosts.Hosts[host]); err != nil {
			return contractresolver.Hosts{}, fmt.Errorf("insert dns host %q failed: %w", host, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return contractresolver.Hosts{}, fmt.Errorf("commit dns hosts transaction failed: %w", err)
	}
	return hosts, nil
}

func (s *ResolverConfigStore) FakeDNS(ctx context.Context) (contractresolver.FakeDNS, error) {
	if s == nil || s.db == nil {
		return contractresolver.FakeDNS{}, errors.New("resolver config store database is nil")
	}
	var out contractresolver.FakeDNS
	var enabled int
	err := s.db.QueryRowContext(ctx, `
		SELECT fakedns_enabled, fakedns_ipv4_range, fakedns_ipv6_range
		FROM dns_settings
		WHERE id = 1
	`).Scan(&enabled, &out.IPv4Range, &out.IPv6Range)
	if errors.Is(err, sql.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return contractresolver.FakeDNS{}, fmt.Errorf("query fakedns settings failed: %w", err)
	}
	out.Enabled = enabled != 0

	rows, err := s.db.QueryContext(ctx, `
		SELECT kind, value
		FROM dns_fakedns_lists
		ORDER BY rowid
	`)
	if err != nil {
		return contractresolver.FakeDNS{}, fmt.Errorf("query fakedns lists failed: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var kind, value string
		if err := rows.Scan(&kind, &value); err != nil {
			return contractresolver.FakeDNS{}, fmt.Errorf("scan fakedns list failed: %w", err)
		}
		switch kind {
		case "whitelist":
			out.Whitelist = append(out.Whitelist, value)
		case "skip_check":
			out.SkipCheckList = append(out.SkipCheckList, value)
		}
	}
	if err := rows.Err(); err != nil {
		return contractresolver.FakeDNS{}, fmt.Errorf("iterate fakedns lists failed: %w", err)
	}
	return out, nil
}

func (s *ResolverConfigStore) SaveFakeDNS(ctx context.Context, config contractresolver.FakeDNS) (contractresolver.FakeDNS, error) {
	if s == nil || s.db == nil {
		return contractresolver.FakeDNS{}, errors.New("resolver config store database is nil")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return contractresolver.FakeDNS{}, fmt.Errorf("begin fakedns transaction failed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO dns_settings(id, server, fakedns_enabled, fakedns_ipv4_range, fakedns_ipv6_range)
		VALUES (1, '', ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			fakedns_enabled = excluded.fakedns_enabled,
			fakedns_ipv4_range = excluded.fakedns_ipv4_range,
			fakedns_ipv6_range = excluded.fakedns_ipv6_range
	`, boolToInt(config.Enabled), config.IPv4Range, config.IPv6Range); err != nil {
		return contractresolver.FakeDNS{}, fmt.Errorf("save fakedns settings failed: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM dns_fakedns_lists`); err != nil {
		return contractresolver.FakeDNS{}, fmt.Errorf("clear fakedns lists failed: %w", err)
	}
	for _, value := range config.Whitelist {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO dns_fakedns_lists(kind, value)
			VALUES ('whitelist', ?)
		`, value); err != nil {
			return contractresolver.FakeDNS{}, fmt.Errorf("insert fakedns whitelist %q failed: %w", value, err)
		}
	}
	for _, value := range config.SkipCheckList {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO dns_fakedns_lists(kind, value)
			VALUES ('skip_check', ?)
		`, value); err != nil {
			return contractresolver.FakeDNS{}, fmt.Errorf("insert fakedns skip_check %q failed: %w", value, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return contractresolver.FakeDNS{}, fmt.Errorf("commit fakedns transaction failed: %w", err)
	}
	return config, nil
}

func (s *ResolverConfigStore) Server(ctx context.Context) (contractresolver.Server, error) {
	if s == nil || s.db == nil {
		return contractresolver.Server{}, errors.New("resolver config store database is nil")
	}
	var out contractresolver.Server
	err := s.db.QueryRowContext(ctx, `SELECT server FROM dns_settings WHERE id = 1`).Scan(&out.Server)
	if errors.Is(err, sql.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return contractresolver.Server{}, fmt.Errorf("query dns server failed: %w", err)
	}
	return out, nil
}

func (s *ResolverConfigStore) SaveServer(ctx context.Context, server contractresolver.Server) (contractresolver.Server, error) {
	if s == nil || s.db == nil {
		return contractresolver.Server{}, errors.New("resolver config store database is nil")
	}
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO dns_settings(id, server, fakedns_enabled, fakedns_ipv4_range, fakedns_ipv6_range)
		VALUES (1, ?, 0, '', '')
		ON CONFLICT(id) DO UPDATE SET
			server = excluded.server
	`, server.Server); err != nil {
		return contractresolver.Server{}, fmt.Errorf("save dns server failed: %w", err)
	}
	return server, nil
}
