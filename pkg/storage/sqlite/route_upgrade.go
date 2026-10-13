package sqlite

import (
	"context"
	"database/sql"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
)

// LegacyRouteBinding is only used when upgrading stored configurations. Alias
// chains never enter the formal contract or the runtime destination resolver.
type LegacyRouteBinding struct {
	Type string   `json:"type"`
	Hash []string `json:"hash"`
}

func upgradeStoredRouteBindings(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `SELECT name, members_json FROM node_tags_v2`)
	if err != nil {
		return err
	}
	bindings := map[string]LegacyRouteBinding{}
	for rows.Next() {
		var name, value string
		if err := rows.Scan(&name, &value); err != nil {
			_ = rows.Close()
			return err
		}
		var binding LegacyRouteBinding
		if err := json.Unmarshal([]byte(value), &binding); err != nil {
			_ = rows.Close()
			return err
		}
		bindings[name] = binding
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return err
	}
	if err := UpgradeRouteSelectors(ctx, tx, bindings); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `ALTER TABLE route_rules_v2 DROP COLUMN tag`); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `DROP TABLE node_tags_v2`)
	return err
}

// UpgradeRouteSelectors is shared by the schema upgrade and the one-time
// legacy importer, which runs after legacy nodes have been imported.
func UpgradeRouteSelectors(ctx context.Context, tx *sql.Tx, bindings map[string]LegacyRouteBinding) error {
	destinations := map[string]contractroute.Target{}
	for _, name := range slices.Sorted(maps.Keys(bindings)) {
		root := name
		seen := map[string]bool{}
		for {
			if seen[root] {
				return fmt.Errorf("legacy destination %q contains an alias cycle", name)
			}
			seen[root] = true
			binding, exists := bindings[root]
			if !exists || len(binding.Hash) == 0 {
				destinations[name] = contractroute.Target{Type: "default"}
				break
			}
			if binding.Type == "mirror" {
				root = binding.Hash[0]
				continue
			}
			nodeIDs := []string{}
			for _, id := range binding.Hash {
				var present string
				err := tx.QueryRowContext(ctx, `SELECT id FROM nodes_v2 WHERE id = ?`, id).Scan(&present)
				if errors.Is(err, sql.ErrNoRows) {
					continue
				}
				if err != nil {
					return err
				}
				if !slices.Contains(nodeIDs, id) {
					nodeIDs = append(nodeIDs, id)
				}
			}
			if len(nodeIDs) == 0 {
				destinations[name] = contractroute.Target{Type: "default"}
				break
			}
			selected := nodeIDs[0]
			if len(nodeIDs) > 1 {
				selected = "legacy-set:" + root
				node := contractnode.Node{ID: selected, Name: root, Group: "Imported destinations", Origin: "manual", Enabled: true, Chain: []contractnode.Protocol{{Type: "set", Set: &contractnode.Set{Nodes: nodeIDs, Strategy: "random"}}}}
				value, err := json.Marshal(node)
				if err != nil {
					return err
				}
				if _, err := tx.ExecContext(ctx, `INSERT INTO nodes_v2(id, name, group_name, origin, enabled, chain_types_json, updated_at, data_json) VALUES (?, ?, ?, ?, 1, '["set"]', ?, ?) ON CONFLICT(id) DO NOTHING`, node.ID, node.Name, node.Group, node.Origin, time.Now().Unix(), string(value)); err != nil {
					return err
				}
			}
			id := "legacy-selector:" + root
			if _, err := tx.ExecContext(ctx, `INSERT INTO outbound_selectors(id, name, node_id, revision) VALUES (?, ?, ?, 1) ON CONFLICT(id) DO NOTHING`, id, root, selected); err != nil {
				return err
			}
			destinations[name] = contractroute.Target{Type: "selector", ID: id}
			break
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT id, data_json FROM route_rules_v2`)
	if err != nil {
		return err
	}
	type storedRule struct{ id, value string }
	rules := []storedRule{}
	for rows.Next() {
		var row storedRule
		if err := rows.Scan(&row.id, &row.value); err != nil {
			_ = rows.Close()
			return err
		}
		rules = append(rules, row)
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return err
	}
	for _, stored := range rules {
		var old struct {
			contractroute.RouteRule
			Tag string `json:"tag"`
		}
		if err := json.Unmarshal([]byte(stored.value), &old); err != nil {
			return err
		}
		rule := old.RouteRule
		if rule.ID == "" {
			rule.ID = stored.id
		}
		if rule.Revision == 0 {
			rule.Revision = 1
		}
		switch rule.Target.Type {
		case "":
			rule.Target = contractroute.Target{Type: "default"}
			if target, exists := destinations[old.Tag]; exists {
				rule.Target = target
			}
		case "selector":
			if target, exists := destinations[rule.Target.ID]; exists {
				rule.Target = target
			}
		}
		if rule.Mode == "bypass" || rule.Mode == "" {
			rule.Mode = "proxy"
		}
		if rule.Mode != "proxy" {
			rule.Target = contractroute.Target{Type: "default"}
		}
		for i := range rule.Rules {
			rule.Rules[i] = upgradeEmptyConditions(rule.Rules[i])
		}
		value, err := json.Marshal(rule)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE route_rules_v2 SET action_mode = ?, data_json = ? WHERE id = ?`, rule.Mode, string(value), stored.id); err != nil {
			return err
		}
	}
	return nil
}

func upgradeEmptyConditions(expr contractroute.RuleExpr) contractroute.RuleExpr {
	if expr.Type == "all" && len(expr.All) == 0 {
		return contractroute.RuleExpr{Type: "always", Always: &contractroute.MatchAllExpr{}}
	}
	for i := range expr.All {
		expr.All[i] = upgradeEmptyConditions(expr.All[i])
	}
	for i := range expr.Any {
		expr.Any[i] = upgradeEmptyConditions(expr.Any[i])
	}
	if expr.Not != nil {
		next := upgradeEmptyConditions(*expr.Not)
		expr.Not = &next
	}
	return expr
}
