package store

import (
	"context"
	"database/sql"
	json "encoding/json/v2"
	"errors"
	"fmt"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"time"
)

type RouteSettingsStore struct {
	db *sql.DB
}

type RouteSettings struct {
	Revision       uint64
	DefaultMode    string
	DefaultTarget  contractroute.Target
	DirectResolver string
	ProxyResolver  string
	ResolveLocally bool
	UDPProxyFQDN   int
}

type RouteListSettings struct {
	Revision             uint64
	RefreshInterval      uint64
	LastRefreshTime      uint64
	Error                string
	HostIndexDisk        bool
	MaxMindDBDownloadURL string
	MaxMindDBError       string
}

type routeRefreshConfigJSON struct {
	Revision        uint64 `json:"revision"`
	RefreshInterval uint64 `json:"refresh_interval"`
	LastRefreshTime uint64 `json:"last_refresh_time"`
	Error           string `json:"error"`
	HostIndexDisk   *bool  `json:"host_index_disk"`
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
	return readRouteSettings(ctx, s.db)
}

type routeQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func readRouteSettings(ctx context.Context, q routeQueryer) (RouteSettings, error) {
	out := RouteSettings{DefaultMode: "proxy", DefaultTarget: contractroute.Target{Type: "default"}}
	var resolveLocally int
	var targetJSON string
	err := q.QueryRowContext(ctx, `
		SELECT direct_resolver, proxy_resolver, resolve_locally, udp_proxy_fqdn, revision, default_mode, default_target_json
		FROM route_settings
		WHERE id = 1
	`).Scan(&out.DirectResolver, &out.ProxyResolver, &resolveLocally, &out.UDPProxyFQDN, &out.Revision, &out.DefaultMode, &targetJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return RouteSettings{}, fmt.Errorf("query route settings failed: %w", err)
	}
	out.ResolveLocally = resolveLocally != 0
	if err := json.Unmarshal([]byte(targetJSON), &out.DefaultTarget); err != nil {
		return RouteSettings{}, err
	}
	return out, nil
}

func (s *RouteSettingsStore) SaveSettings(ctx context.Context, settings RouteSettings) error {
	if s == nil || s.db == nil {
		return errors.New("route settings store database is nil")
	}
	return saveRouteSettings(ctx, s.db, settings)
}

func saveRouteSettings(ctx context.Context, execer NodeExecer, settings RouteSettings) error {
	if settings.DefaultMode == "" {
		settings.DefaultMode = "proxy"
	}
	if settings.DefaultTarget.Type == "" {
		settings.DefaultTarget.Type = "default"
	}
	target, err := json.Marshal(settings.DefaultTarget)
	if err != nil {
		return err
	}
	if _, err := execer.ExecContext(ctx, `
		INSERT INTO route_settings(id, direct_resolver, proxy_resolver, resolve_locally, udp_proxy_fqdn, revision, default_mode, default_target_json)
		VALUES (1, ?, ?, ?, ?, 1, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			direct_resolver = excluded.direct_resolver,
			proxy_resolver = excluded.proxy_resolver,
			resolve_locally = excluded.resolve_locally,
			udp_proxy_fqdn = excluded.udp_proxy_fqdn,
			revision = route_settings.revision + 1,
			default_mode = excluded.default_mode,
			default_target_json = excluded.default_target_json
	`, settings.DirectResolver, settings.ProxyResolver, boolToInt(settings.ResolveLocally), settings.UDPProxyFQDN, settings.DefaultMode, string(target)); err != nil {
		return fmt.Errorf("save route settings failed: %w", err)
	}
	return nil
}

func (s *RouteSettingsStore) ListSettings(ctx context.Context) (RouteListSettings, error) {
	if s == nil || s.db == nil {
		return RouteListSettings{}, errors.New("route settings store database is nil")
	}
	// Disk-backed host indexes are the default. A nil pointer below keeps old
	// settings, which predate this option, on the same default without
	// overriding an explicit false saved by the user.
	return readRouteListSettings(ctx, s.db)
}

func readRouteListSettings(ctx context.Context, q routeQueryer) (RouteListSettings, error) {
	out := RouteListSettings{HostIndexDisk: true}
	if err := loadRefreshConfig(ctx, q, &out); err != nil {
		return RouteListSettings{}, err
	}
	if err := loadMaxMindDB(ctx, q, &out); err != nil {
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

	if err := saveRouteListSettings(ctx, tx, settings, now); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit route list settings transaction failed: %w", err)
	}
	return nil
}

func saveRouteListSettings(ctx context.Context, tx *sql.Tx, settings RouteListSettings, now int64) error {
	hostIndexDisk := settings.HostIndexDisk
	refresh := &routeRefreshConfigJSON{
		Revision:        settings.Revision,
		RefreshInterval: settings.RefreshInterval,
		LastRefreshTime: settings.LastRefreshTime,
		Error:           settings.Error,
		HostIndexDisk:   &hostIndexDisk,
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
	return nil
}

func loadRefreshConfig(ctx context.Context, q routeQueryer, out *RouteListSettings) error {
	var data string
	err := q.QueryRowContext(ctx, `
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
	out.Revision = refresh.Revision
	out.LastRefreshTime = refresh.LastRefreshTime
	out.Error = refresh.Error
	if refresh.HostIndexDisk != nil {
		out.HostIndexDisk = *refresh.HostIndexDisk
	}
	return nil
}

func loadMaxMindDB(ctx context.Context, q routeQueryer, out *RouteListSettings) error {
	var data string
	err := q.QueryRowContext(ctx, `
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
