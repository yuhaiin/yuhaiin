package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/Asutorufa/yuhaiin/pkg/security/configchange"
	"strings"
	"time"
	"uuid"

	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
)

var ErrConflict = errors.New("configuration changed; reload before saving")

type ResourceInUseError struct {
	References []contractroute.Reference
}

func (e *ResourceInUseError) Error() string {
	names := make([]string, 0, len(e.References))
	for _, ref := range e.References {
		names = append(names, ref.Name)
	}
	return "resource is used by: " + strings.Join(names, ", ")
}

// RouteEditorStore owns rule/list lifecycle and transactions. It deliberately
// has no dependency on matching indexes or proxy implementations.
type RouteEditorStore struct{ db *sql.DB }

func NewRouteEditorStore(db *sql.DB) *RouteEditorStore { return &RouteEditorStore{db: db} }

func (s *RouteEditorStore) Get(ctx context.Context, id string) (contractroute.RuleDraft, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return contractroute.RuleDraft{}, err
	}
	defer func() { _ = tx.Rollback() }()
	draft, err := readRouteDraft(ctx, tx, id)
	if err != nil {
		return draft, err
	}
	return draft, tx.Commit()
}
func readRouteDraft(ctx context.Context, tx *sql.Tx, id string) (contractroute.RuleDraft, error) {
	var value string
	if err := tx.QueryRowContext(ctx, `SELECT data_json FROM route_rules_v2 WHERE id = ?`, id).Scan(&value); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return contractroute.RuleDraft{}, ErrNotFound
		}
		return contractroute.RuleDraft{}, err
	}
	rule, err := decodeRouteRule(value)
	if err != nil {
		return contractroute.RuleDraft{}, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT data_json FROM route_lists_v2 WHERE owner_rule_id = ? ORDER BY id`, id)
	if err != nil {
		return contractroute.RuleDraft{}, err
	}
	defer rows.Close()
	draft := contractroute.RuleDraft{Rule: rule, Lists: []contractroute.RouteListDetail{}}
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return contractroute.RuleDraft{}, err
		}
		list, err := decodeRouteListDetail(value)
		if err != nil {
			return contractroute.RuleDraft{}, err
		}
		draft.Lists = append(draft.Lists, list)
	}
	if err := rows.Err(); err != nil {
		return contractroute.RuleDraft{}, err
	}
	if err := rows.Close(); err != nil {
		return contractroute.RuleDraft{}, err
	}
	return draft, nil
}

func (s *RouteEditorStore) Save(ctx context.Context, draft contractroute.RuleDraft) (contractroute.RuleDraft, error) {
	if draft.Rule.ID == "" {
		draft.Rule.ID = configchange.NewResourceID(ctx, uuid.New().String())
	}
	expectedRevision := draft.Rule.Revision
	draft.Rule = normalizeRouteRule(draft.Rule)
	if err := validateRouteRule(draft.Rule); err != nil {
		return contractroute.RuleDraft{}, err
	}
	if err := contractroute.ValidateConditions(draft.Rule.Rules); err != nil {
		return contractroute.RuleDraft{}, err
	}
	tx, err := configchange.Begin(ctx, s.db, "route-rule")
	if err != nil {
		return contractroute.RuleDraft{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var before *RouteRuleChange
	if configchange.Managed(ctx) {
		current, e := readRuleChange(ctx, tx, draft.Rule.ID)
		if e == nil {
			before = &current
		} else if !errors.Is(e, ErrNotFound) {
			return contractroute.RuleDraft{}, e
		}
	}
	var revision uint64
	var priority int
	err = tx.QueryRowContext(ctx, `SELECT revision, priority FROM route_rules_v2 WHERE id = ?`, draft.Rule.ID).Scan(&revision, &priority)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return contractroute.RuleDraft{}, err
	}
	if revision != expectedRevision {
		return contractroute.RuleDraft{}, ErrConflict
	}
	if priority == 0 {
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(priority), 0) + 1 FROM route_rules_v2`).Scan(&priority); err != nil {
			return contractroute.RuleDraft{}, err
		}
	}
	if err := validateTarget(ctx, tx, draft.Rule); err != nil {
		return contractroute.RuleDraft{}, err
	}
	if err := validateRuleOptions(ctx, tx, draft.Rule); err != nil {
		return contractroute.RuleDraft{}, err
	}
	owned := make(map[string]contractroute.RouteListDetail, len(draft.Lists))
	for i, list := range draft.Lists {
		if list.ID == "" {
			return contractroute.RuleDraft{}, fmt.Errorf("list %d needs an ID before it can be referenced", i+1)
		}
		if list.OwnerRuleID != "" && list.OwnerRuleID != draft.Rule.ID {
			return contractroute.RuleDraft{}, fmt.Errorf("list belongs to another rule")
		}
		list.OwnerRuleID = draft.Rule.ID
		list = normalizeRouteListDetail(list)
		if err := validateRouteListDetail(list); err != nil {
			return contractroute.RuleDraft{}, err
		}
		if list.Source.Type != "local" {
			return contractroute.RuleDraft{}, fmt.Errorf("use a shared list for remotely refreshed data")
		}
		if _, duplicate := owned[list.ID]; duplicate {
			return contractroute.RuleDraft{}, fmt.Errorf("duplicate list ID %q", list.ID)
		}
		var existingOwner sql.NullString
		err := tx.QueryRowContext(ctx, `SELECT owner_rule_id FROM route_lists_v2 WHERE id = ?`, list.ID).Scan(&existingOwner)
		if err == nil && (!existingOwner.Valid || existingOwner.String != draft.Rule.ID) {
			return contractroute.RuleDraft{}, fmt.Errorf("cannot take ownership of list %q", list.Name)
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return contractroute.RuleDraft{}, err
		}
		owned[list.ID] = list
		draft.Lists[i] = list
	}
	used := make(map[string]bool)
	if err := contractroute.VisitListRefs(draft.Rule.Rules, func(kind, id string) error {
		list, own := owned[id]
		if !own {
			var value string
			var owner sql.NullString
			if err := tx.QueryRowContext(ctx, `SELECT data_json, owner_rule_id FROM route_lists_v2 WHERE id = ?`, id).Scan(&value, &owner); err != nil {
				return fmt.Errorf("list %q is unavailable: %w", id, err)
			}
			if owner.Valid {
				return fmt.Errorf("list %q is private; include its data when editing its owning rule", id)
			}
			var err error
			list, err = decodeRouteListDetail(value)
			if err != nil {
				return err
			}
		}
		if list.Type != kind && (kind != "host" || list.Type != "hosts_as_host") {
			return fmt.Errorf("%s condition cannot use %s list %q", kind, list.Type, list.Name)
		}
		used[id] = true
		return nil
	}); err != nil {
		return contractroute.RuleDraft{}, err
	}
	for id := range owned {
		if !used[id] {
			return contractroute.RuleDraft{}, fmt.Errorf("owned list %q is not used by this rule", id)
		}
	}
	shared := make(map[string]bool, len(draft.ShareLists))
	for _, id := range draft.ShareLists {
		list, ok := owned[id]
		if !ok || !used[id] {
			return contractroute.RuleDraft{}, fmt.Errorf("only this rule's matching data can become shared")
		}
		if strings.TrimSpace(list.Name) == "" {
			return contractroute.RuleDraft{}, fmt.Errorf("shared matching data needs a name")
		}
		if shared[id] {
			return contractroute.RuleDraft{}, fmt.Errorf("duplicate shared list ID %q", id)
		}
		shared[id] = true
	}
	draft.Rule.Revision = revision + 1
	now := time.Now().Unix()
	if err := SaveRouteRuleContract(ctx, tx, draft.Rule, priority, now); err != nil {
		return contractroute.RuleDraft{}, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM route_lists_v2 WHERE owner_rule_id = ?`, draft.Rule.ID); err != nil {
		return contractroute.RuleDraft{}, err
	}
	private := make([]contractroute.RouteListDetail, 0, len(draft.Lists))
	for _, list := range draft.Lists {
		if shared[list.ID] {
			list.OwnerRuleID = ""
			list.Revision++
		} else {
			private = append(private, list)
		}
		if err := SaveRouteListContract(ctx, tx, list, now); err != nil {
			return contractroute.RuleDraft{}, err
		}
	}
	if configchange.Managed(ctx) {
		if e := restoreRulePosition(ctx, tx, draft.Rule.ID); e != nil {
			return contractroute.RuleDraft{}, e
		}
		after, e := readRuleChange(ctx, tx, draft.Rule.ID)
		if e != nil {
			return contractroute.RuleDraft{}, e
		}
		if e = configchange.RecordValues(ctx, s.db, tx, "route-rule", draft.Rule.ID, after.Draft.Rule.Revision, before, after, before, after); e != nil {
			return contractroute.RuleDraft{}, e
		}
	}
	if err := configchange.Commit(ctx, tx); err != nil {
		return contractroute.RuleDraft{}, err
	}
	draft.Lists = private
	draft.ShareLists = nil
	return draft, nil
}

func validateTarget(ctx context.Context, tx *sql.Tx, rule contractroute.RouteRule) error {
	if rule.Mode == "gateway" {
		if rule.ID == "" {
			return errors.New("gateway is only supported as a routing rule action")
		}
		if rule.Target.Type != "gateway" || rule.Target.ID == "" {
			return errors.New("gateway action requires a Gateway destination")
		}
		var found int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM gateway_configuration, json_each(data_json, '$.gateways') g WHERE json_extract(g.value, '$.id')=?`, rule.Target.ID).Scan(&found); err != nil {
			return err
		}
		if found == 0 {
			return fmt.Errorf("gateway %q is unavailable", rule.Target.ID)
		}
		return nil
	}
	if rule.Mode != "proxy" && rule.Mode != "direct" && rule.Mode != "block" {
		return fmt.Errorf("unknown routing action %q", rule.Mode)
	}
	if rule.Mode == "direct" || rule.Mode == "block" {
		if rule.Target.Type != "" && rule.Target.Type != "default" {
			return fmt.Errorf("%s cannot select a proxy destination", rule.Mode)
		}
		if rule.Target.ID != "" {
			return fmt.Errorf("%s cannot contain a destination ID", rule.Mode)
		}
		return nil
	}
	switch rule.Target.Type {
	case "", "default":
		if rule.Target.ID != "" {
			return fmt.Errorf("default destination cannot contain an ID")
		}
	case "node":
		node, err := getNodeContract(ctx, tx, rule.Target.ID)
		if err != nil {
			return err
		}
		if !node.Enabled {
			return fmt.Errorf("node %q is disabled", node.Name)
		}
	case "selector":
		var id string
		if err := tx.QueryRowContext(ctx, `SELECT node_id FROM outbound_selectors WHERE id = ?`, rule.Target.ID).Scan(&id); err != nil {
			return fmt.Errorf("selected outbound is unavailable: %w", err)
		}
		node, err := getNodeContract(ctx, tx, id)
		if err != nil {
			return err
		}
		if !node.Enabled {
			return fmt.Errorf("shared destination uses disabled node %q", node.Name)
		}
	default:
		return fmt.Errorf("unknown destination type %q", rule.Target.Type)
	}
	return nil
}

func validateRuleOptions(ctx context.Context, tx *sql.Tx, rule contractroute.RouteRule) error {
	switch rule.ResolveStrategy {
	case "", "default", "prefer_ipv4", "prefer_ipv6", "only_ipv4", "only_ipv6":
	default:
		return fmt.Errorf("unknown address resolution strategy %q", rule.ResolveStrategy)
	}
	switch rule.UdpProxyFqdnStrategy {
	case "", "default", "resolve", "skip_resolve", "udp_proxy_fqdn_strategy_default", "udp_proxy_fqdn_strategy_resolve", "udp_proxy_fqdn_strategy_skip_resolve":
	default:
		return fmt.Errorf("unknown UDP domain strategy %q", rule.UdpProxyFqdnStrategy)
	}
	if rule.Resolver != "" {
		var exists int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM resolvers_v2 WHERE id = ?`, rule.Resolver).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			return fmt.Errorf("resolver %q is unavailable", rule.Resolver)
		}
	}
	var referenceErr error
	visitInboundRefs(rule.Rules, func(id string) {
		if referenceErr != nil {
			return
		}
		var exists int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM inbounds_v2 WHERE id = ?`, id).Scan(&exists); err != nil {
			referenceErr = err
			return
		}
		if exists == 0 {
			referenceErr = fmt.Errorf("traffic entry %q is unavailable", id)
		}
	})
	if referenceErr != nil {
		return referenceErr
	}
	return nil
}

func listReferences(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, id string) ([]contractroute.Reference, error) {
	entries, err := listRouteRulesTx(ctx, q)
	if err != nil {
		return nil, err
	}
	refs := []contractroute.Reference{}
	for _, entry := range entries {
		found := false
		if err := contractroute.VisitListRefs(entry.Rule.Rules, func(_ string, ref string) error { found = found || ref == id; return nil }); err != nil {
			return nil, err
		}
		if found {
			refs = append(refs, contractroute.Reference{Kind: "rule", ID: entry.Rule.ID, Name: entry.Rule.Name})
		}
	}
	return refs, nil
}
