package store

import (
	"context"
	"database/sql"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
)

type ruleReferenceQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func matchingRuleReferences(ctx context.Context, q ruleReferenceQueryer, uses func(contractroute.RouteRule) bool) ([]contractroute.Reference, error) {
	rows, err := q.QueryContext(ctx, `SELECT data_json, 0 FROM route_rules_v2
		UNION ALL SELECT r.value, 1 FROM route_configuration_state s, json_each(s.applied_rules_json) r ORDER BY 2`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	refs := []contractroute.Reference{}
	saved := map[string]bool{}
	for rows.Next() {
		var data string
		var running int
		if err := rows.Scan(&data, &running); err != nil {
			return nil, err
		}
		rule, err := decodeRouteRule(data)
		if err != nil {
			return nil, err
		}
		if !uses(rule) || running == 1 && saved[rule.ID] {
			continue
		}
		name := rule.Name
		if running == 1 {
			name += " (running)"
		} else {
			saved[rule.ID] = true
		}
		refs = append(refs, contractroute.Reference{Kind: "rule", ID: rule.ID, Name: name})
	}
	return refs, rows.Err()
}

func ResolverReferences(ctx context.Context, q ruleReferenceQueryer, id string) ([]contractroute.Reference, error) {
	refs, err := matchingRuleReferences(ctx, q, func(rule contractroute.RouteRule) bool { return rule.Resolver == id })
	if err != nil {
		return nil, err
	}
	rows, err := q.QueryContext(ctx, `SELECT 'route-direct-dns', 'Direct traffic DNS' FROM route_settings WHERE direct_resolver = ?
		UNION ALL SELECT 'route-proxy-dns', 'Proxy traffic DNS' FROM route_settings WHERE proxy_resolver = ?
		UNION ALL SELECT 'route-direct-dns', 'Direct traffic DNS (running)' FROM route_configuration_state WHERE json_extract(applied_config_json, '$.directResolver') = ? AND NOT EXISTS(SELECT 1 FROM route_settings WHERE direct_resolver = ?)
		UNION ALL SELECT 'route-proxy-dns', 'Proxy traffic DNS (running)' FROM route_configuration_state WHERE json_extract(applied_config_json, '$.proxyResolver') = ? AND NOT EXISTS(SELECT 1 FROM route_settings WHERE proxy_resolver = ?)`, id, id, id, id, id, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		ref := contractroute.Reference{Kind: "default"}
		if err := rows.Scan(&ref.ID, &ref.Name); err != nil {
			return nil, err
		}
		refs = append(refs, ref)
	}
	return refs, rows.Err()
}

func InboundReferences(ctx context.Context, q ruleReferenceQueryer, id string) ([]contractroute.Reference, error) {
	refs, err := matchingRuleReferences(ctx, q, func(rule contractroute.RouteRule) bool {
		found := false
		visitInboundRefs(rule.Rules, func(ref string) { found = found || ref == id })
		return found
	})
	if err != nil {
		return nil, err
	}
	rows, err := q.QueryContext(ctx, `SELECT owner_id,owner_name FROM gateway_references WHERE inbound_id=?`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		ref := contractroute.Reference{Kind: "gateway"}
		if err := rows.Scan(&ref.ID, &ref.Name); err != nil {
			return nil, err
		}
		refs = append(refs, ref)
	}
	return refs, rows.Err()
}

func visitInboundRefs(rules []contractroute.RuleExpr, visit func(string)) {
	for _, expr := range rules {
		if expr.Inbound != nil {
			if expr.Inbound.Name != "" {
				visit(expr.Inbound.Name)
			}
			for _, id := range expr.Inbound.Names {
				visit(id)
			}
		}
		visitInboundRefs(expr.All, visit)
		visitInboundRefs(expr.Any, visit)
		if expr.Not != nil {
			visitInboundRefs([]contractroute.RuleExpr{*expr.Not}, visit)
		}
	}
}
