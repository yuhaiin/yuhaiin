package store

import (
	"context"
	"database/sql"
	"encoding/json/v2"
	"slices"

	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/security/configchange"
)

type RouteRuleChange struct {
	Draft    contractroute.RuleDraft `json:"draft"`
	Priority int                     `json:"priority"`
}

func readRuleChange(ctx context.Context, tx *sql.Tx, id string) (RouteRuleChange, error) {
	draft, err := readRouteDraft(ctx, tx, id)
	if err != nil {
		return RouteRuleChange{}, err
	}
	var priority int
	err = tx.QueryRowContext(ctx, `SELECT priority FROM route_rules_v2 WHERE id=?`, id).Scan(&priority)
	return RouteRuleChange{Draft: draft, Priority: priority}, err
}
func (s *RouteRuleStore) RuleChange(ctx context.Context, id string) (RouteRuleChange, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return RouteRuleChange{}, err
	}
	defer func() { _ = tx.Rollback() }()
	return readRuleChange(ctx, tx, id)
}
func canonicalList(value contractroute.RouteListDetail) contractroute.RouteListDetail {
	value.ErrorMsgs = nil
	return value
}
func publicList(value contractroute.RouteListDetail) contractroute.RouteListDetail {
	value = canonicalList(value)
	if value.Source.Remote != nil {
		remote := *value.Source.Remote
		remote.URLs = slices.Clone(remote.URLs)
		for i := range remote.URLs {
			remote.URLs[i] = "[redacted URL]"
		}
		value.Source.Remote = &remote
	}
	return value
}
func recordListChange(ctx context.Context, db *sql.DB, tx *sql.Tx, id string, before *contractroute.RouteListDetail, after *contractroute.RouteListDetail, revision uint64) error {
	var privateBefore, privateAfter, publicBefore, publicAfter any
	if before != nil {
		v := canonicalList(*before)
		privateBefore = v
		publicBefore = publicList(v)
	}
	if after != nil {
		v := canonicalList(*after)
		privateAfter = v
		changed := before == nil
		if before != nil {
			old, _ := json.Marshal(before.Source, json.Deterministic(true))
			next, _ := json.Marshal(after.Source, json.Deterministic(true))
			changed = string(old) != string(next)
		}
		publicAfter = struct {
			contractroute.RouteListDetail
			SourceChanged bool `json:"sourceChanged"`
		}{RouteListDetail: publicList(v), SourceChanged: changed}
	}
	return configchange.RecordValues(ctx, db, tx, "route-list", id, revision, privateBefore, privateAfter, publicBefore, publicAfter)
}
func routeSettingsPolicy(v RouteSettings) contractroute.Config {
	strategy := "default"
	switch v.UDPProxyFQDN {
	case 1:
		strategy = "resolve"
	case 2:
		strategy = "skip_resolve"
	}
	return contractroute.Config{Revision: v.Revision, DefaultMode: v.DefaultMode, DefaultTarget: v.DefaultTarget, DirectResolver: v.DirectResolver, ProxyResolver: v.ProxyResolver, ResolveLocally: v.ResolveLocally, UdpProxyFqdnStrategy: strategy}
}

type RouteOrderEntry struct {
	ID       string `json:"id"`
	Revision uint64 `json:"revision"`
}

func routeOrder(entries []RouteRuleEntry) []RouteOrderEntry {
	out := make([]RouteOrderEntry, 0, len(entries))
	for _, entry := range entries {
		out = append(out, RouteOrderEntry{ID: entry.Rule.ID, Revision: entry.Rule.Revision})
	}
	return out
}
func (s *RouteRuleStore) Order(ctx context.Context) ([]RouteOrderEntry, error) {
	entries, err := s.ListRules(ctx)
	return routeOrder(entries), err
}
func recordRouteOrder(ctx context.Context, db *sql.DB, tx *sql.Tx, before, after []RouteRuleEntry) error {
	if !configchange.Managed(ctx) {
		return nil
	}
	var revision uint64
	if err := tx.QueryRowContext(ctx, `SELECT saved_revision FROM route_configuration_state WHERE id=1`).Scan(&revision); err != nil {
		return err
	}
	return configchange.RecordValues(ctx, db, tx, "route-order", "order", revision, routeOrder(before), routeOrder(after), routeOrder(before), routeOrder(after))
}

// SaveOrder changes only ordering and requires an exact permutation of current IDs.
func (s *RouteRuleStore) SaveOrder(ctx context.Context, ids []string) error {
	tx, err := configchange.Begin(ctx, s.db, "route-order")
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	before, err := listRouteRulesTx(ctx, tx)
	if err != nil {
		return err
	}
	if len(ids) != len(before) {
		return configchange.ErrConflict
	}
	byID := make(map[string]RouteRuleEntry, len(before))
	for _, entry := range before {
		byID[entry.Rule.ID] = entry
	}
	after := make([]RouteRuleEntry, 0, len(ids))
	for _, id := range ids {
		entry, ok := byID[id]
		if !ok {
			return configchange.ErrConflict
		}
		delete(byID, id)
		after = append(after, entry)
	}
	if err = rewriteRouteRuleOrderTx(ctx, tx, after); err != nil {
		return err
	}
	if err = recordRouteOrder(ctx, s.db, tx, before, after); err != nil {
		return err
	}
	return configchange.Commit(ctx, tx)
}

type rulePositionKey struct{}

func WithRulePosition(ctx context.Context, position int) context.Context {
	return context.WithValue(ctx, rulePositionKey{}, position)
}
func restoreRulePosition(ctx context.Context, tx *sql.Tx, id string) error {
	position, _ := ctx.Value(rulePositionKey{}).(int)
	if position < 1 {
		return nil
	}
	entries, err := listRouteRulesTx(ctx, tx)
	if err != nil {
		return err
	}
	index := slices.IndexFunc(entries, func(entry RouteRuleEntry) bool { return entry.Rule.ID == id })
	if index < 0 {
		return ErrNotFound
	}
	entry := entries[index]
	entries = append(entries[:index], entries[index+1:]...)
	target := min(position-1, len(entries))
	entries = append(entries, RouteRuleEntry{})
	copy(entries[target+1:], entries[target:])
	entries[target] = entry
	return rewriteRouteRuleOrderTx(ctx, tx, entries)
}
