package store

import (
	"context"
	"database/sql"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"github.com/Asutorufa/yuhaiin/pkg/security/configchange"
	"strings"
	"time"

	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
)

type RouteListStore struct {
	db *sql.DB
}

type RouteListExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func NewRouteListStore(db *sql.DB) *RouteListStore {
	return &RouteListStore{db: db}
}

func (s *RouteListStore) ListRouteLists(ctx context.Context) ([]contractroute.ListItem, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("route list store database is nil")
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT data_json
		FROM route_lists_v2
		WHERE owner_rule_id IS NULL
		ORDER BY name
	`)
	if err != nil {
		return nil, fmt.Errorf("query route list contracts failed: %w", err)
	}
	defer rows.Close()

	var out []contractroute.ListItem
	for rows.Next() {
		var dataJSON string
		if err := rows.Scan(&dataJSON); err != nil {
			return nil, fmt.Errorf("scan route list contract failed: %w", err)
		}
		detail, err := decodeRouteListDetail(dataJSON)
		if err != nil {
			return nil, err
		}
		out = append(out, routeListItemFromDetail(detail))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate route list contracts failed: %w", err)
	}
	return out, nil
}

func (s *RouteListStore) ListRouteListDetails(ctx context.Context) ([]contractroute.RouteListDetail, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("route list store database is nil")
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT data_json
		FROM route_lists_v2
		ORDER BY name
	`)
	if err != nil {
		return nil, fmt.Errorf("query route list contracts failed: %w", err)
	}
	defer rows.Close()

	var out []contractroute.RouteListDetail
	for rows.Next() {
		var dataJSON string
		if err := rows.Scan(&dataJSON); err != nil {
			return nil, fmt.Errorf("scan route list contract failed: %w", err)
		}
		detail, err := decodeRouteListDetail(dataJSON)
		if err != nil {
			return nil, err
		}
		out = append(out, detail)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate route list contracts failed: %w", err)
	}
	return out, nil
}

func (s *RouteListStore) GetRouteList(ctx context.Context, name string) (contractroute.RouteListDetail, error) {
	if s == nil || s.db == nil {
		return contractroute.RouteListDetail{}, errors.New("route list store database is nil")
	}
	var dataJSON string
	err := s.db.QueryRowContext(ctx, `SELECT data_json FROM route_lists_v2 WHERE id = ?`, name).Scan(&dataJSON)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return contractroute.RouteListDetail{}, fmt.Errorf("%w: route list %s not found", ErrNotFound, name)
	case err != nil:
		return contractroute.RouteListDetail{}, fmt.Errorf("query route list %q failed: %w", name, err)
	}
	return decodeRouteListDetail(dataJSON)
}

func (s *RouteListStore) SaveRouteList(ctx context.Context, detail contractroute.RouteListDetail, updatedAt int64) error {
	if s == nil || s.db == nil {
		return errors.New("route list store database is nil")
	}
	if detail.OwnerRuleID != "" {
		return errors.New("edit a private list through its owning rule")
	}
	detail = normalizeRouteListDetail(detail)
	tx, err := configchange.Begin(ctx, s.db, "route-list")
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var before *contractroute.RouteListDetail
	var owner sql.NullString
	var data string
	err = tx.QueryRowContext(ctx, `SELECT owner_rule_id, data_json FROM route_lists_v2 WHERE id = ?`, detail.ID).Scan(&owner, &data)
	if err == nil && owner.Valid {
		return errors.New("edit a private list through its owning rule")
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil {
		current, err := decodeRouteListDetail(data)
		if err != nil {
			return err
		}
		if current.Revision != detail.Revision {
			return ErrConflict
		}
		detail.ErrorMsgs = current.ErrorMsgs
		before = &current
	} else if detail.Revision != 0 {
		return ErrConflict
	}
	detail.Revision++
	if err := SaveRouteListContract(ctx, tx, detail, updatedAt); err != nil {
		return err
	}
	if configchange.Managed(ctx) {
		var actual string
		if err := tx.QueryRowContext(ctx, `SELECT data_json FROM route_lists_v2 WHERE id=?`, detail.ID).Scan(&actual); err != nil {
			return err
		}
		after, err := decodeRouteListDetail(actual)
		if err != nil {
			return err
		}
		if err = recordListChange(ctx, s.db, tx, detail.ID, before, &after, after.Revision); err != nil {
			return err
		}
	}
	return configchange.Commit(ctx, tx)
}

func SaveRouteListContract(ctx context.Context, execer RouteListExecer, detail contractroute.RouteListDetail, updatedAt int64) error {
	if handled, err := protectedTransaction(ctx, execer, func(q any) error { return SaveRouteListContract(ctx, q.(RouteListExecer), detail, updatedAt) }); handled {
		return err
	}
	var err error
	detail, err = mergeProtected(ctx, execer, detail, `SELECT data_json FROM route_lists_v2 WHERE id=?`, detail.ID)
	if err != nil {
		return err
	}
	detail = normalizeRouteListDetail(detail)
	if err := validateRouteListDetail(detail); err != nil {
		return err
	}
	if updatedAt == 0 {
		updatedAt = time.Now().Unix()
	}
	dataJSON, err := json.Marshal(detail)
	if err != nil {
		return fmt.Errorf("encode route list %q failed: %w", detail.Name, err)
	}
	result, err := execer.ExecContext(ctx, `
		INSERT INTO route_lists_v2(id, name, owner_rule_id, list_type, source_type, updated_at, data_json)
		VALUES (?, ?, NULLIF(?, ''), ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name = excluded.name,
			owner_rule_id = excluded.owner_rule_id,
			list_type = excluded.list_type,
			source_type = excluded.source_type,
			updated_at = excluded.updated_at,
			data_json = excluded.data_json
		WHERE route_lists_v2.owner_rule_id IS excluded.owner_rule_id
	`, detail.ID, detail.Name, detail.OwnerRuleID, detail.Type, detail.Source.Type, updatedAt, string(dataJSON))
	if err != nil {
		return fmt.Errorf("upsert route list %q failed: %w", detail.Name, err)
	}
	if n, err := result.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return errors.New("list ownership cannot be changed by this operation")
	}
	return nil
}

func (s *RouteListStore) DeleteRouteList(ctx context.Context, name string) error {
	if s == nil || s.db == nil {
		return errors.New("route list store database is nil")
	}
	tx, err := configchange.Begin(ctx, s.db, "route-list")
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var before *contractroute.RouteListDetail
	if configchange.Managed(ctx) {
		var raw string
		if err := tx.QueryRowContext(ctx, `SELECT data_json FROM route_lists_v2 WHERE id=?`, name).Scan(&raw); err != nil {
			return err
		}
		v, err := decodeRouteListDetail(raw)
		if err != nil {
			return err
		}
		before = &v
	}
	var owner sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT owner_rule_id FROM route_lists_v2 WHERE id = ?`, name).Scan(&owner); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: list %s", ErrNotFound, name)
		}
		return err
	}
	if owner.Valid {
		return errors.New("delete a private list through its owning rule")
	}
	refs, err := listReferences(ctx, tx, name)
	if err != nil {
		return err
	}
	if len(refs) > 0 {
		return &ResourceInUseError{References: refs}
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM route_lists_v2 WHERE id = ?`, name)
	if err != nil {
		return fmt.Errorf("delete route list %q failed: %w", name, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: route list %s not found", ErrNotFound, name)
	}
	if before != nil {
		if err := recordListChange(ctx, s.db, tx, name, before, nil, before.Revision+1); err != nil {
			return err
		}
	}
	return configchange.Commit(ctx, tx)
}

func decodeRouteListDetail(dataJSON string) (contractroute.RouteListDetail, error) {
	var detail contractroute.RouteListDetail
	if err := json.Unmarshal([]byte(dataJSON), &detail); err != nil {
		return contractroute.RouteListDetail{}, fmt.Errorf("decode route list contract failed: %w", err)
	}
	detail = normalizeRouteListDetail(detail)
	if err := validateRouteListDetail(detail); err != nil {
		return contractroute.RouteListDetail{}, err
	}
	return detail, nil
}

func normalizeRouteListDetail(detail contractroute.RouteListDetail) contractroute.RouteListDetail {
	detail.Name = strings.TrimSpace(detail.Name)
	detail.ID = strings.TrimSpace(detail.ID)
	if detail.ID == "" {
		detail.ID = detail.Name
	}
	if strings.TrimSpace(detail.Type) == "" {
		detail.Type = "host"
	}
	if strings.TrimSpace(detail.Source.Type) == "" {
		detail.Source.Type = "local"
	}
	switch detail.Source.Type {
	case "remote":
		if detail.Source.Remote == nil {
			detail.Source.Remote = &contractroute.RemoteSource{}
		}
		detail.Source.Local = nil
	default:
		detail.Source.Type = "local"
		if detail.Source.Local == nil {
			detail.Source.Local = &contractroute.LocalSource{}
		}
		detail.Source.Remote = nil
	}
	return detail
}

func validateRouteListDetail(detail contractroute.RouteListDetail) error {
	if strings.TrimSpace(detail.Name) == "" {
		return errors.New("route list name is empty")
	}
	return nil
}

func routeListItemFromDetail(detail contractroute.RouteListDetail) contractroute.ListItem {
	item := contractroute.ListItem{
		ID:          detail.ID,
		OwnerRuleID: detail.OwnerRuleID,
		Name:        detail.Name,
		Type:        detail.Type,
		Source:      detail.Source.Type,
		ErrorCount:  uint32(len(detail.ErrorMsgs)),
	}
	switch detail.Source.Type {
	case "remote":
		if detail.Source.Remote != nil {
			item.ItemCount = uint32(len(detail.Source.Remote.URLs))
			item.Preview = firstString(detail.Source.Remote.URLs)
		}
	default:
		if detail.Source.Local != nil {
			item.ItemCount = uint32(len(detail.Source.Local.Lists))
			item.Preview = firstString(detail.Source.Local.Lists)
		}
	}
	return item
}

func firstString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
