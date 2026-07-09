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

type RouteRuleStore struct {
	db *sql.DB
}

type RouteRuleEntry struct {
	Rule     contractroute.RouteRule
	Priority int
}

func NewRouteRuleStore(db *sql.DB) *RouteRuleStore {
	return &RouteRuleStore{db: db}
}

func (s *RouteRuleStore) ListRules(ctx context.Context) ([]RouteRuleEntry, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("route rule store database is nil")
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT priority, data_json
		FROM route_rules_v2
		ORDER BY priority, name
	`)
	if err != nil {
		return nil, fmt.Errorf("query route rule contracts failed: %w", err)
	}
	defer rows.Close()

	var out []RouteRuleEntry
	for rows.Next() {
		var priority int
		var dataJSON string
		if err := rows.Scan(&priority, &dataJSON); err != nil {
			return nil, fmt.Errorf("scan route rule contract failed: %w", err)
		}
		rule, err := decodeRouteRule(dataJSON)
		if err != nil {
			return nil, err
		}
		out = append(out, RouteRuleEntry{Rule: rule, Priority: priority})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate route rule contracts failed: %w", err)
	}
	return out, nil
}

func (s *RouteRuleStore) GetRule(ctx context.Context, name string) (RouteRuleEntry, error) {
	if s == nil || s.db == nil {
		return RouteRuleEntry{}, errors.New("route rule store database is nil")
	}
	var priority int
	var dataJSON string
	err := s.db.QueryRowContext(ctx, `
		SELECT priority, data_json
		FROM route_rules_v2
		WHERE name = ?
	`, name).Scan(&priority, &dataJSON)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return RouteRuleEntry{}, fmt.Errorf("%w: route rule %s not found", ErrNotFound, name)
	case err != nil:
		return RouteRuleEntry{}, fmt.Errorf("query route rule %q failed: %w", name, err)
	}
	rule, err := decodeRouteRule(dataJSON)
	if err != nil {
		return RouteRuleEntry{}, err
	}
	return RouteRuleEntry{Rule: rule, Priority: priority}, nil
}

func (s *RouteRuleStore) SaveRule(ctx context.Context, rule contractroute.RouteRule, priority int, updatedAt int64) error {
	if s == nil || s.db == nil {
		return errors.New("route rule store database is nil")
	}
	rule = normalizeRouteRule(rule)
	if err := validateRouteRule(rule); err != nil {
		return err
	}
	if updatedAt == 0 {
		updatedAt = time.Now().Unix()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin route rule save transaction failed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if priority <= 0 {
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(priority), 0) + 1 FROM route_rules_v2`).Scan(&priority); err != nil {
			return fmt.Errorf("query next route rule priority failed: %w", err)
		}
	}
	if err := SaveRouteRuleContract(ctx, tx, rule, priority, updatedAt); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit route rule save transaction failed: %w", err)
	}
	return nil
}

func (s *RouteRuleStore) DeleteRule(ctx context.Context, name string) error {
	if s == nil || s.db == nil {
		return errors.New("route rule store database is nil")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin route rule delete transaction failed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `DELETE FROM route_rules_v2 WHERE name = ?`, name)
	if err != nil {
		return fmt.Errorf("delete route rule %q failed: %w", name, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: route rule %s not found", ErrNotFound, name)
	}
	if err := renumberRouteRulesTx(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit route rule delete transaction failed: %w", err)
	}
	return nil
}

func (s *RouteRuleStore) ChangePriority(ctx context.Context, sourceName, targetName, operate string) error {
	if s == nil || s.db == nil {
		return errors.New("route rule store database is nil")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin route priority transaction failed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	entries, err := listRouteRulesTx(ctx, tx)
	if err != nil {
		return err
	}
	sourceIndex, targetIndex := -1, -1
	for i, entry := range entries {
		if entry.Rule.Name == sourceName {
			sourceIndex = i
		}
		if entry.Rule.Name == targetName {
			targetIndex = i
		}
	}
	if sourceIndex < 0 {
		return fmt.Errorf("%w: route rule %s not found", ErrNotFound, sourceName)
	}
	if targetIndex < 0 {
		return fmt.Errorf("%w: route rule %s not found", ErrNotFound, targetName)
	}

	switch operate {
	case "", "exchange":
		entries[sourceIndex], entries[targetIndex] = entries[targetIndex], entries[sourceIndex]
	case "insert_before", "insert_after":
		source := entries[sourceIndex]
		entries = append(entries[:sourceIndex], entries[sourceIndex+1:]...)
		targetIndex = -1
		for i, entry := range entries {
			if entry.Rule.Name == targetName {
				targetIndex = i
				break
			}
		}
		if targetIndex < 0 {
			return fmt.Errorf("%w: route rule %s not found", ErrNotFound, targetName)
		}
		insertAt := targetIndex
		if operate == "insert_after" {
			insertAt = targetIndex + 1
		}
		entries = append(entries, RouteRuleEntry{})
		copy(entries[insertAt+1:], entries[insertAt:])
		entries[insertAt] = source
	default:
		return fmt.Errorf("unknown priority operate %q", operate)
	}
	if err := rewriteRouteRuleOrderTx(ctx, tx, entries); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit route priority transaction failed: %w", err)
	}
	return nil
}

func SaveRouteRuleContract(ctx context.Context, execer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, rule contractroute.RouteRule, priority int, updatedAt int64) error {
	rule = normalizeRouteRule(rule)
	if err := validateRouteRule(rule); err != nil {
		return err
	}
	dataJSON, err := json.Marshal(rule)
	if err != nil {
		return fmt.Errorf("encode route rule %q failed: %w", rule.Name, err)
	}
	matchType := "empty"
	if len(rule.Rules) == 1 {
		matchType = rule.Rules[0].Type
	} else if len(rule.Rules) > 1 {
		matchType = "all"
	}
	if _, err := execer.ExecContext(ctx, `
		INSERT INTO route_rules_v2(id, name, priority, disabled, action_mode, match_type, tag, updated_at, data_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name = excluded.name,
			priority = excluded.priority,
			disabled = excluded.disabled,
			action_mode = excluded.action_mode,
			match_type = excluded.match_type,
			tag = excluded.tag,
			updated_at = excluded.updated_at,
			data_json = excluded.data_json
	`, rule.Name, rule.Name, priority, boolToInt(rule.Disabled), rule.Mode, matchType, rule.Tag, updatedAt, string(dataJSON)); err != nil {
		return fmt.Errorf("upsert route rule %q failed: %w", rule.Name, err)
	}
	return nil
}

func listRouteRulesTx(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) ([]RouteRuleEntry, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT priority, data_json
		FROM route_rules_v2
		ORDER BY priority, name
	`)
	if err != nil {
		return nil, fmt.Errorf("query route rule contracts failed: %w", err)
	}
	defer rows.Close()
	var entries []RouteRuleEntry
	for rows.Next() {
		var priority int
		var dataJSON string
		if err := rows.Scan(&priority, &dataJSON); err != nil {
			return nil, fmt.Errorf("scan route rule contract failed: %w", err)
		}
		rule, err := decodeRouteRule(dataJSON)
		if err != nil {
			return nil, err
		}
		entries = append(entries, RouteRuleEntry{Rule: rule, Priority: priority})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate route rule contracts failed: %w", err)
	}
	return entries, nil
}

func rewriteRouteRuleOrderTx(ctx context.Context, tx *sql.Tx, entries []RouteRuleEntry) error {
	for i, entry := range entries {
		if _, err := tx.ExecContext(ctx, `UPDATE route_rules_v2 SET priority = ? WHERE name = ?`, -(i + 1), entry.Rule.Name); err != nil {
			return fmt.Errorf("stage route rule %q priority failed: %w", entry.Rule.Name, err)
		}
	}
	for i, entry := range entries {
		if _, err := tx.ExecContext(ctx, `UPDATE route_rules_v2 SET priority = ? WHERE name = ?`, i+1, entry.Rule.Name); err != nil {
			return fmt.Errorf("update route rule %q priority failed: %w", entry.Rule.Name, err)
		}
	}
	return nil
}

func renumberRouteRulesTx(ctx context.Context, tx *sql.Tx) error {
	entries, err := listRouteRulesTx(ctx, tx)
	if err != nil {
		return err
	}
	return rewriteRouteRuleOrderTx(ctx, tx, entries)
}

func decodeRouteRule(dataJSON string) (contractroute.RouteRule, error) {
	var rule contractroute.RouteRule
	if err := json.Unmarshal([]byte(dataJSON), &rule); err != nil {
		return contractroute.RouteRule{}, fmt.Errorf("decode route rule contract failed: %w", err)
	}
	rule = normalizeRouteRule(rule)
	if err := validateRouteRule(rule); err != nil {
		return contractroute.RouteRule{}, err
	}
	return rule, nil
}

func normalizeRouteRule(rule contractroute.RouteRule) contractroute.RouteRule {
	rule.Name = strings.TrimSpace(rule.Name)
	if strings.TrimSpace(rule.Mode) == "" {
		rule.Mode = "bypass"
	}
	return rule
}

func validateRouteRule(rule contractroute.RouteRule) error {
	if strings.TrimSpace(rule.Name) == "" {
		return errors.New("route rule name is empty")
	}
	return nil
}
