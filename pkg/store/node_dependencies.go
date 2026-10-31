package store

import (
	"context"
	"database/sql"
	"encoding/json/v2"
	"fmt"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
)

// validateNodeDependencies rejects Set and point-as-endpoint cycles before
// constructing runtime proxies. Selectors refer only to Node IDs, so they
// cannot introduce a separate selector-to-selector namespace or bypass this.
func validateNodeDependencies(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) error {
	rows, err := q.QueryContext(ctx, `SELECT id,data_json FROM nodes_v2`)
	if err != nil {
		return err
	}
	edges := map[string][]string{}
	for rows.Next() {
		var id, raw string
		if err := rows.Scan(&id, &raw); err != nil {
			_ = rows.Close()
			return err
		}
		var n contract.Node
		if err := json.Unmarshal([]byte(raw), &n); err != nil {
			_ = rows.Close()
			return err
		}
		edges[id] = nil
		for _, p := range n.Chain {
			edges[id] = append(edges[id], protocolDependencies(p)...)
		}
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return err
	}
	state := make(map[string]uint8, len(edges))
	var visit func(string, int) error
	visit = func(id string, depth int) error {
		if state[id] == 1 {
			return fmt.Errorf("recursive node dependency at %q", id)
		}
		if state[id] == 2 {
			return nil
		}
		if depth > 64 {
			return fmt.Errorf("node dependency depth exceeds 64 at %q", id)
		}
		state[id] = 1
		for _, to := range edges[id] {
			if err := visit(to, depth+1); err != nil {
				return err
			}
		}
		state[id] = 2
		return nil
	}
	for id := range edges {
		if err := visit(id, 0); err != nil {
			return err
		}
	}
	return nil
}

func protocolDependencies(p contract.Protocol) []string {
	var ids []string
	if p.Set != nil {
		ids = append(ids, p.Set.Nodes...)
	}
	if p.PointAsEndpoint != nil && p.PointAsEndpoint.Hash != "" {
		ids = append(ids, p.PointAsEndpoint.Hash)
	}
	if p.NetworkSplit != nil {
		for _, child := range []*contract.Protocol{p.NetworkSplit.TCP, p.NetworkSplit.UDP} {
			if child != nil {
				ids = append(ids, protocolDependencies(*child)...)
			}
		}
	}
	return ids
}
