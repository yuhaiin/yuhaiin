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
	err := s.db.QueryRowContext(ctx, `SELECT data_json FROM route_lists_v2 WHERE name = ?`, name).Scan(&dataJSON)
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
	return SaveRouteListContract(ctx, s.db, detail, updatedAt)
}

func SaveRouteListContract(ctx context.Context, execer RouteListExecer, detail contractroute.RouteListDetail, updatedAt int64) error {
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
	if _, err := execer.ExecContext(ctx, `
		INSERT INTO route_lists_v2(name, list_type, source_type, updated_at, data_json)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET
			list_type = excluded.list_type,
			source_type = excluded.source_type,
			updated_at = excluded.updated_at,
			data_json = excluded.data_json
	`, detail.Name, detail.Type, detail.Source.Type, updatedAt, string(dataJSON)); err != nil {
		return fmt.Errorf("upsert route list %q failed: %w", detail.Name, err)
	}
	return nil
}

func (s *RouteListStore) DeleteRouteList(ctx context.Context, name string) error {
	if s == nil || s.db == nil {
		return errors.New("route list store database is nil")
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM route_lists_v2 WHERE name = ?`, name)
	if err != nil {
		return fmt.Errorf("delete route list %q failed: %w", name, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: route list %s not found", ErrNotFound, name)
	}
	return nil
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
		Name:       detail.Name,
		Type:       detail.Type,
		Source:     detail.Source.Type,
		ErrorCount: uint32(len(detail.ErrorMsgs)),
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
