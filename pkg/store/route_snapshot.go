package store

import (
	"context"
	"database/sql"
	json "encoding/json/v2"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/security/configchange"
	"maps"
	"slices"
)

// RouteSnapshot contains all persisted input for one matcher generation. Lists
// still own index construction; the snapshot only supplies immutable data.
type RouteSnapshot struct {
	Revision     uint64
	Rules        []RouteRuleEntry
	Lists        []contractroute.RouteListDetail
	Settings     RouteSettings
	ListSettings RouteListSettings
}

func (s *RouteRuleStore) Snapshot(ctx context.Context) (RouteSnapshot, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return RouteSnapshot{}, err
	}
	defer func() { _ = tx.Rollback() }()
	snapshot, err := ReadRouteSnapshot(ctx, tx)
	if err != nil {
		return snapshot, err
	}
	return snapshot, tx.Commit()
}

// ReadRouteSnapshot also reads an uncommitted, validated candidate for atomic
// configuration activation. It never opens another database connection.
func ReadRouteSnapshot(ctx context.Context, tx *sql.Tx) (RouteSnapshot, error) {
	var err error
	var snapshot RouteSnapshot
	if err := tx.QueryRowContext(ctx, `SELECT saved_revision FROM route_configuration_state WHERE id = 1`).Scan(&snapshot.Revision); err != nil {
		return snapshot, err
	}
	if snapshot.Rules, err = listRouteRulesTx(ctx, tx); err != nil {
		return snapshot, err
	}
	if snapshot.Settings, err = readRouteSettings(ctx, tx); err != nil {
		return snapshot, err
	}
	if snapshot.ListSettings, err = readRouteListSettings(ctx, tx); err != nil {
		return snapshot, err
	}
	ids := map[string]struct{}{}
	for _, entry := range snapshot.Rules {
		if entry.Rule.Disabled {
			continue
		}
		if err := contractroute.VisitListRefs(entry.Rule.Rules, func(_ string, id string) error { ids[id] = struct{}{}; return nil }); err != nil {
			return snapshot, err
		}
	}
	encodedIDs, err := json.Marshal(slices.Sorted(maps.Keys(ids)))
	if err != nil {
		return snapshot, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT data_json FROM route_lists_v2 WHERE id IN (SELECT value FROM json_each(?)) ORDER BY id`, string(encodedIDs))
	if err != nil {
		return snapshot, err
	}
	defer rows.Close()
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return snapshot, err
		}
		list, err := decodeRouteListDetail(data)
		if err != nil {
			return snapshot, err
		}
		snapshot.Lists = append(snapshot.Lists, list)
	}
	if err := rows.Err(); err != nil {
		return snapshot, err
	}
	if err := rows.Close(); err != nil {
		return snapshot, err
	}
	return snapshot, nil
}

func (s *RouteRuleStore) ConfigurationRevision(ctx context.Context) (uint64, error) {
	var revision uint64
	err := s.db.QueryRowContext(ctx, `SELECT saved_revision FROM route_configuration_state WHERE id = 1`).Scan(&revision)
	return revision, err
}

// ActivateSnapshot rejects a stale build and commits its marker before the
// non-failing runtime swap. Subsequent edits have a greater saved revision.
func (s *RouteRuleStore) ActivateSnapshot(ctx context.Context, revision uint64, install func()) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := MarkRouteSnapshot(ctx, tx, revision); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	install()
	return nil
}

// MarkRouteSnapshot is part of the same target/history transaction when the
// configuration workflow prepares a candidate before committing it.
func MarkRouteSnapshot(ctx context.Context, tx *sql.Tx, revision uint64) error {
	result, err := tx.ExecContext(ctx, `UPDATE route_configuration_state SET applied_revision = ? WHERE id = 1 AND saved_revision = ?`, revision, revision)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrConflict
	}
	rules, err := listRouteRulesTx(ctx, tx)
	if err != nil {
		return err
	}
	active := []contractroute.RouteRule{}
	for _, entry := range rules {
		if !entry.Rule.Disabled {
			active = append(active, entry.Rule)
		}
	}
	rulesJSON, err := json.Marshal(active)
	if err != nil {
		return err
	}
	settings, err := readRouteSettings(ctx, tx)
	if err != nil {
		return err
	}
	configJSON, err := json.Marshal(contractroute.Config{Revision: settings.Revision, DefaultMode: settings.DefaultMode, DefaultTarget: settings.DefaultTarget, DirectResolver: settings.DirectResolver, ProxyResolver: settings.ProxyResolver})
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE route_configuration_state SET applied_rules_json = ?, applied_config_json = ? WHERE id = 1`, string(rulesJSON), string(configJSON)); err != nil {
		return err
	}
	return nil
}

func (s *RouteRuleStore) ResetActivation(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `UPDATE route_configuration_state SET applied_revision = 0, applied_rules_json = '[]', applied_config_json = '{}' WHERE id = 1`)
	return err
}

func (s *RouteSettingsStore) SaveConfig(ctx context.Context, config contractroute.Config) (RouteSettings, error) {
	tx, err := configchange.Begin(ctx, s.db, "route-defaults")
	if err != nil {
		return RouteSettings{}, err
	}
	defer func() { _ = tx.Rollback() }()
	current, err := readRouteSettings(ctx, tx)
	if err != nil {
		return current, err
	}
	if config.Revision != current.Revision {
		return current, ErrConflict
	}
	mode := config.DefaultMode
	if mode == "" {
		mode = "proxy"
	}
	target := config.DefaultTarget
	if target.Type == "" {
		target.Type = "default"
	}
	if err := validateTarget(ctx, tx, contractroute.RouteRule{Mode: mode, Target: target}); err != nil {
		return current, err
	}
	if err := validateRuleOptions(ctx, tx, contractroute.RouteRule{Resolver: config.DirectResolver, UdpProxyFqdnStrategy: config.UdpProxyFqdnStrategy}); err != nil {
		return current, err
	}
	if err := validateRuleOptions(ctx, tx, contractroute.RouteRule{Resolver: config.ProxyResolver}); err != nil {
		return current, err
	}
	udp := 0
	switch config.UdpProxyFqdnStrategy {
	case "resolve", "udp_proxy_fqdn_strategy_resolve":
		udp = 1
	case "skip_resolve", "udp_proxy_fqdn_strategy_skip_resolve":
		udp = 2
	}
	value := RouteSettings{DefaultMode: mode, DefaultTarget: target, DirectResolver: config.DirectResolver, ProxyResolver: config.ProxyResolver, ResolveLocally: config.ResolveLocally, UDPProxyFQDN: udp}
	if err := saveRouteSettings(ctx, tx, value); err != nil {
		return value, err
	}
	value, err = readRouteSettings(ctx, tx)
	if err != nil {
		return value, err
	}
	if err := configchange.RecordValues(ctx, s.db, tx, "route-defaults", "route-defaults", value.Revision, current, value, routeSettingsPolicy(current), routeSettingsPolicy(value)); err != nil {
		return value, err
	}
	return value, configchange.Commit(ctx, tx)
}
