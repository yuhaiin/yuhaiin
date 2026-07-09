package store

import (
	"context"
	"database/sql"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"time"
)

type RouteSettingsStore struct {
	db *sql.DB
}

type RouteSettings struct {
	DirectResolver string
	ProxyResolver  string
	ResolveLocally bool
	UDPProxyFQDN   int
}

type RouteListSettings struct {
	RefreshInterval      uint64
	LastRefreshTime      uint64
	Error                string
	MaxMindDBDownloadURL string
	MaxMindDBError       string
}

type routeRefreshConfigJSON struct {
	RefreshInterval uint64 `json:"refresh_interval"`
	LastRefreshTime uint64 `json:"last_refresh_time"`
	Error           string `json:"error"`
}

type maxminddbGeoIPJSON struct {
	DownloadURL string `json:"download_url"`
	Error       string `json:"error"`
}

func NewRouteSettingsStore(db *sql.DB) *RouteSettingsStore {
	return &RouteSettingsStore{db: db}
}

func (s *RouteSettingsStore) Settings(ctx context.Context) (RouteSettings, error) {
	if s == nil || s.db == nil {
		return RouteSettings{}, errors.New("route settings store database is nil")
	}
	var out RouteSettings
	var resolveLocally int
	err := s.db.QueryRowContext(ctx, `
		SELECT direct_resolver, proxy_resolver, resolve_locally, udp_proxy_fqdn
		FROM route_settings
		WHERE id = 1
	`).Scan(&out.DirectResolver, &out.ProxyResolver, &resolveLocally, &out.UDPProxyFQDN)
	if errors.Is(err, sql.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return RouteSettings{}, fmt.Errorf("query route settings failed: %w", err)
	}
	out.ResolveLocally = resolveLocally != 0
	return out, nil
}

func (s *RouteSettingsStore) SaveSettings(ctx context.Context, settings RouteSettings) error {
	if s == nil || s.db == nil {
		return errors.New("route settings store database is nil")
	}
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO route_settings(id, direct_resolver, proxy_resolver, resolve_locally, udp_proxy_fqdn)
		VALUES (1, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			direct_resolver = excluded.direct_resolver,
			proxy_resolver = excluded.proxy_resolver,
			resolve_locally = excluded.resolve_locally,
			udp_proxy_fqdn = excluded.udp_proxy_fqdn
	`, settings.DirectResolver, settings.ProxyResolver, boolToInt(settings.ResolveLocally), settings.UDPProxyFQDN); err != nil {
		return fmt.Errorf("save route settings failed: %w", err)
	}
	return nil
}

func (s *RouteSettingsStore) ListSettings(ctx context.Context) (RouteListSettings, error) {
	if s == nil || s.db == nil {
		return RouteListSettings{}, errors.New("route settings store database is nil")
	}
	out := RouteListSettings{}
	if err := s.loadRefreshConfig(ctx, &out); err != nil {
		return RouteListSettings{}, err
	}
	if err := s.loadMaxMindDB(ctx, &out); err != nil {
		return RouteListSettings{}, err
	}
	return out, nil
}

func (s *RouteSettingsStore) SaveListSettings(ctx context.Context, settings RouteListSettings) error {
	if s == nil || s.db == nil {
		return errors.New("route settings store database is nil")
	}
	now := time.Now().Unix()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin route list settings transaction failed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	refresh := &routeRefreshConfigJSON{
		RefreshInterval: settings.RefreshInterval,
		LastRefreshTime: settings.LastRefreshTime,
		Error:           settings.Error,
	}
	if err := saveSettingsKV(ctx, tx, "route_extra", "refresh_config", refresh, now); err != nil {
		return err
	}
	geoip := &maxminddbGeoIPJSON{
		DownloadURL: settings.MaxMindDBDownloadURL,
		Error:       settings.MaxMindDBError,
	}
	if err := saveSettingsKV(ctx, tx, "route_extra", "maxminddb_geoip", geoip, now); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit route list settings transaction failed: %w", err)
	}
	return nil
}

func (s *RouteSettingsStore) loadRefreshConfig(ctx context.Context, out *RouteListSettings) error {
	var data string
	err := s.db.QueryRowContext(ctx, `
		SELECT value_json
		FROM settings_kv
		WHERE section = 'route_extra' AND key = 'refresh_config'
	`).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("query route refresh config failed: %w", err)
	}
	var refresh routeRefreshConfigJSON
	if err := json.Unmarshal([]byte(data), &refresh); err != nil {
		return fmt.Errorf("decode route refresh config failed: %w", err)
	}
	out.RefreshInterval = refresh.RefreshInterval
	out.LastRefreshTime = refresh.LastRefreshTime
	out.Error = refresh.Error
	return nil
}

func (s *RouteSettingsStore) loadMaxMindDB(ctx context.Context, out *RouteListSettings) error {
	var data string
	err := s.db.QueryRowContext(ctx, `
		SELECT value_json
		FROM settings_kv
		WHERE section = 'route_extra' AND key = 'maxminddb_geoip'
	`).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("query maxminddb geoip config failed: %w", err)
	}
	var geoip maxminddbGeoIPJSON
	if err := json.Unmarshal([]byte(data), &geoip); err != nil {
		return fmt.Errorf("decode maxminddb geoip config failed: %w", err)
	}
	out.MaxMindDBDownloadURL = geoip.DownloadURL
	out.MaxMindDBError = geoip.Error
	return nil
}

func saveSettingsKV(ctx context.Context, tx *sql.Tx, section, key string, value any, updatedAt int64) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode %s.%s failed: %w", section, key, err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO settings_kv(section, key, value_json, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(section, key) DO UPDATE SET
			value_json = excluded.value_json,
			updated_at = excluded.updated_at
	`, section, key, string(data), updatedAt); err != nil {
		return fmt.Errorf("save %s.%s failed: %w", section, key, err)
	}
	return nil
}
