package migrate

import (
	"context"
	"database/sql"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"time"

	contractinbound "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	legacyconfig "github.com/Asutorufa/yuhaiin/pkg/legacy/schema/config"
	legacynode "github.com/Asutorufa/yuhaiin/pkg/legacy/schema/node"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

func MigrateLegacyInbounds(ctx context.Context, db *sql.DB, updatedAt int64) ([]Warning, error) {
	if db == nil {
		return nil, errors.New("database is nil")
	}
	if updatedAt == 0 {
		updatedAt = time.Now().Unix()
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin legacy inbound migration failed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, `
		SELECT name, inbound_type, data_json
		FROM inbounds
		ORDER BY name
	`)
	if err != nil {
		return nil, fmt.Errorf("query legacy inbounds failed: %w", err)
	}

	var warnings []Warning
	for rows.Next() {
		var name, inboundType, dataJSON string
		if err := rows.Scan(&name, &inboundType, &dataJSON); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("scan legacy inbound failed: %w", err)
		}

		var old legacyconfig.Inbound
		if err := json.Unmarshal([]byte(dataJSON), &old); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("decode legacy inbound %q failed: %w", name, err)
		}
		applyLegacyInboundTypeFallback(&old, inboundType)
		transportWarnings := dropEmptyLegacyTransports(name, &old)
		old.SetName(name)

		inbound, itemWarnings, err := ConvertLegacyInbound(name, &old)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		warnings = append(warnings, transportWarnings...)
		warnings = append(warnings, itemWarnings...)
		if err := plainstore.SaveInboundContract(ctx, tx, inbound, updatedAt); err != nil {
			_ = rows.Close()
			return nil, err
		}
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close legacy inbound rows failed: %w", err)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate legacy inbounds failed: %w", err)
	}

	if err := markMigrationDone(ctx, tx, "plain_inbounds_migration_done"); err != nil {
		return nil, fmt.Errorf("mark legacy inbound migration done failed: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit legacy inbound migration failed: %w", err)
	}
	return warnings, nil
}

func MigrateLegacyNodes(ctx context.Context, db *sql.DB, updatedAt int64) error {
	done, err := loadMigrationMarker(ctx, db, "plain_nodes_migration_done")
	if err != nil {
		return err
	}
	if done == "1" {
		legacyCount, contractCount, err := migrationCounts(ctx, db, "nodes", "nodes_v2")
		if err != nil {
			return err
		}
		if legacyCount == 0 || legacyCount == contractCount {
			return syncLegacySelectedNodes(ctx, db)
		}
		fmt.Printf("plain node migration warning: legacy nodes=%d, nodes_v2=%d; rebuilding node contracts\n", legacyCount, contractCount)
	}
	if updatedAt == 0 {
		updatedAt = time.Now().Unix()
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin plain node migration transaction failed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM nodes_v2`); err != nil {
		return fmt.Errorf("clear node contracts failed: %w", err)
	}

	rows, err := tx.QueryContext(ctx, `SELECT data_json FROM nodes ORDER BY id`)
	if err != nil {
		return fmt.Errorf("query legacy nodes failed: %w", err)
	}
	defer rows.Close()

	seen := map[string]struct{}{}
	for rows.Next() {
		var dataJSON string
		if err := rows.Scan(&dataJSON); err != nil {
			return fmt.Errorf("scan legacy node failed: %w", err)
		}
		var old legacynode.Point
		if err := json.Unmarshal([]byte(dataJSON), &old); err != nil {
			return fmt.Errorf("decode legacy node failed: %w", err)
		}
		node, warnings, err := ConvertLegacyNode(&old)
		if err != nil {
			return err
		}
		if _, exists := seen[node.ID]; exists {
			return fmt.Errorf("duplicate node id %q during plain migration", node.ID)
		}
		seen[node.ID] = struct{}{}
		for _, warning := range warnings {
			fmt.Printf("plain node migration warning: %s: %s\n", warning.Entity, warning.Message)
		}
		if err := plainstore.SaveNodeContract(ctx, tx, node, updatedAt); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate legacy nodes failed: %w", err)
	}
	if err := syncLegacySelectedNodes(ctx, tx); err != nil {
		return err
	}
	if err := markMigrationDone(ctx, tx, "plain_nodes_migration_done"); err != nil {
		return fmt.Errorf("mark plain node migration done failed: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit plain node migration transaction failed: %w", err)
	}
	return nil
}

func syncLegacySelectedNodes(ctx context.Context, execer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}) error {
	if err := syncLegacySelectedNode(ctx, execer, "selected_tcp_node_v2", "selected_tcp"); err != nil {
		return err
	}
	return syncLegacySelectedNode(ctx, execer, "selected_udp_node_v2", "selected_udp")
}

func syncLegacySelectedNode(ctx context.Context, execer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, metadataKey, legacyColumn string) error {
	_, err := execer.ExecContext(ctx, fmt.Sprintf(`
		INSERT INTO metadata(key, value)
		SELECT ?, hash
		FROM nodes
		WHERE %[1]s = 1
			AND EXISTS (SELECT 1 FROM nodes_v2 WHERE id = nodes.hash)
		LIMIT 1
		ON CONFLICT(key) DO UPDATE SET value = excluded.value
		WHERE metadata.value = ''
			OR NOT EXISTS (SELECT 1 FROM nodes_v2 WHERE id = metadata.value)
	`, legacyColumn), metadataKey)
	if err != nil {
		return fmt.Errorf("sync legacy selected node %q failed: %w", metadataKey, err)
	}
	return nil
}

func MigrateLegacyResolvers(ctx context.Context, db *sql.DB, updatedAt int64) error {
	done, err := loadMigrationMarker(ctx, db, "plain_resolvers_migration_done")
	if err != nil {
		return err
	}
	if done == "1" {
		return nil
	}
	if updatedAt == 0 {
		updatedAt = time.Now().Unix()
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin resolver migration transaction failed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM resolvers_v2`); err != nil {
		return fmt.Errorf("clear resolver contracts failed: %w", err)
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT name, data_json
		FROM dns_resolvers
		ORDER BY name
	`)
	if err != nil {
		return fmt.Errorf("query legacy resolvers failed: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name, dataJSON string
		if err := rows.Scan(&name, &dataJSON); err != nil {
			return fmt.Errorf("scan legacy resolver failed: %w", err)
		}
		var old legacyconfig.Dns
		if err := json.Unmarshal([]byte(dataJSON), &old); err != nil {
			return fmt.Errorf("decode legacy resolver %q failed: %w", name, err)
		}
		resolver, err := ConvertLegacyResolver(name, &old)
		if err != nil {
			return err
		}
		if err := plainstore.SaveResolverContract(ctx, tx, resolver, updatedAt); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate legacy resolvers failed: %w", err)
	}
	if err := markMigrationDone(ctx, tx, "plain_resolvers_migration_done"); err != nil {
		return fmt.Errorf("mark resolver migration done failed: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit resolver migration transaction failed: %w", err)
	}
	return nil
}

func MigrateLegacyRouteRules(ctx context.Context, db *sql.DB, updatedAt int64) error {
	done, err := loadMigrationMarker(ctx, db, "plain_route_rules_migration_done")
	if err != nil {
		return err
	}
	if done == "1" {
		legacyCount, contractCount, err := migrationCounts(ctx, db, "route_rules", "route_rules_v2")
		if err != nil {
			return err
		}
		if legacyCount == 0 || legacyCount == contractCount {
			return nil
		}
		fmt.Printf("plain route rule migration warning: legacy route_rules=%d, route_rules_v2=%d; rebuilding rule contracts\n", legacyCount, contractCount)
	}
	if updatedAt == 0 {
		updatedAt = time.Now().Unix()
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin route rule migration transaction failed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM route_rules_v2`); err != nil {
		return fmt.Errorf("clear route rule contracts failed: %w", err)
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT name, priority, data_json
		FROM route_rules
		ORDER BY priority, name
	`)
	if err != nil {
		return fmt.Errorf("query legacy route rules failed: %w", err)
	}
	defer rows.Close()

	seen := map[string]struct{}{}
	for rows.Next() {
		var name string
		var priority int
		var dataJSON string
		if err := rows.Scan(&name, &priority, &dataJSON); err != nil {
			return fmt.Errorf("scan legacy route rule failed: %w", err)
		}
		var old legacyconfig.Rulev2
		if err := json.Unmarshal([]byte(dataJSON), &old); err != nil {
			return fmt.Errorf("decode legacy route rule %q failed: %w", name, err)
		}
		rule := ConvertLegacyRule(&old)
		if rule.Name == "" {
			rule.Name = name
		}
		if _, ok := seen[rule.Name]; ok {
			return fmt.Errorf("duplicate route rule %q during plain migration", rule.Name)
		}
		seen[rule.Name] = struct{}{}
		priority = len(seen)
		if err := plainstore.SaveRouteRuleContract(ctx, tx, rule, priority, updatedAt); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate legacy route rules failed: %w", err)
	}
	if err := renumberRouteRules(ctx, tx); err != nil {
		return err
	}
	if err := markMigrationDone(ctx, tx, "plain_route_rules_migration_done"); err != nil {
		return fmt.Errorf("mark route rule migration done failed: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit route rule migration transaction failed: %w", err)
	}
	return nil
}

func MigrateLegacyRouteLists(ctx context.Context, db *sql.DB, updatedAt int64) error {
	done, err := loadMigrationMarker(ctx, db, "plain_route_lists_migration_done")
	if err != nil {
		return err
	}
	if done == "1" {
		return nil
	}
	if updatedAt == 0 {
		updatedAt = time.Now().Unix()
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin route list migration transaction failed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM route_lists_v2`); err != nil {
		return fmt.Errorf("clear route list contracts failed: %w", err)
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT name, data_json
		FROM route_lists
		ORDER BY name
	`)
	if err != nil {
		return fmt.Errorf("query legacy route lists failed: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name, dataJSON string
		if err := rows.Scan(&name, &dataJSON); err != nil {
			return fmt.Errorf("scan legacy route list failed: %w", err)
		}
		var old legacyconfig.List
		if err := json.Unmarshal([]byte(dataJSON), &old); err != nil {
			return fmt.Errorf("decode legacy route list %q failed: %w", name, err)
		}
		detail := ConvertLegacyListDetail(&old)
		if detail.Name == "" {
			detail.Name = name
		}
		if err := plainstore.SaveRouteListContract(ctx, tx, detail, updatedAt); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate legacy route lists failed: %w", err)
	}
	if err := markMigrationDone(ctx, tx, "plain_route_lists_migration_done"); err != nil {
		return fmt.Errorf("mark route list migration done failed: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit route list migration transaction failed: %w", err)
	}
	return nil
}

func MigrateLegacyRouteTags(ctx context.Context, db *sql.DB, updatedAt int64) error {
	done, err := loadMigrationMarker(ctx, db, "plain_route_tags_migration_done")
	if err != nil {
		return err
	}
	if done == "1" {
		return nil
	}
	if updatedAt == 0 {
		updatedAt = time.Now().Unix()
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tag migration transaction failed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM node_tags_v2`); err != nil {
		return fmt.Errorf("clear tag contracts failed: %w", err)
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT tag_name, target_kind, target_id
		FROM node_tags
		ORDER BY tag_name, target_kind, target_id
	`)
	if err != nil {
		return fmt.Errorf("query legacy node tags failed: %w", err)
	}
	defer rows.Close()

	tags := map[string]contractroute.TagItem{}
	for rows.Next() {
		var name, kind, target string
		if err := rows.Scan(&name, &kind, &target); err != nil {
			return fmt.Errorf("scan legacy node tag failed: %w", err)
		}
		item := tags[name]
		if item.Name == "" {
			item = contractroute.TagItem{Name: name, Type: "node"}
		}
		if kind == "tag" {
			item.Type = "mirror"
		}
		item.Hash = append(item.Hash, target)
		tags[name] = item
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate legacy node tags failed: %w", err)
	}
	for _, item := range tags {
		if err := plainstore.SaveRouteTagContract(ctx, tx, item, updatedAt); err != nil {
			return err
		}
	}
	if err := markMigrationDone(ctx, tx, "plain_route_tags_migration_done"); err != nil {
		return fmt.Errorf("mark tag migration done failed: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tag migration transaction failed: %w", err)
	}
	return nil
}

func applyLegacyInboundTypeFallback(inbound *legacyconfig.Inbound, inboundType string) {
	if inbound == nil {
		return
	}
	switch inboundType {
	case contractinbound.ProtocolHTTP:
		if inbound.WhichProtocol() == legacyconfig.Inbound_Protocol_not_set_case {
			inbound.SetHttp(&legacyconfig.Http{})
		}
	case contractinbound.ProtocolSocks5:
		if inbound.WhichProtocol() == legacyconfig.Inbound_Protocol_not_set_case {
			inbound.SetSocks5(&legacyconfig.Socks5{})
		}
	case contractinbound.ProtocolYuubinsya:
		if inbound.WhichProtocol() == legacyconfig.Inbound_Protocol_not_set_case {
			inbound.SetYuubinsya(&legacyconfig.Yuubinsya{})
		}
	case contractinbound.ProtocolMixed:
		if inbound.WhichProtocol() == legacyconfig.Inbound_Protocol_not_set_case {
			inbound.SetMix(&legacyconfig.Mixed{})
		}
	case contractinbound.ProtocolSocks4A:
		if inbound.WhichProtocol() == legacyconfig.Inbound_Protocol_not_set_case {
			inbound.SetSocks4A(&legacyconfig.Socks4A{})
		}
	case contractinbound.ProtocolTProxy:
		if inbound.WhichProtocol() == legacyconfig.Inbound_Protocol_not_set_case {
			inbound.SetTproxy(&legacyconfig.Tproxy{})
		}
	case contractinbound.ProtocolRedir:
		if inbound.WhichProtocol() == legacyconfig.Inbound_Protocol_not_set_case {
			inbound.SetRedir(&legacyconfig.Redir{})
		}
	case contractinbound.ProtocolTun:
		if inbound.WhichProtocol() == legacyconfig.Inbound_Protocol_not_set_case {
			inbound.SetTun(&legacyconfig.Tun{})
		}
	case contractinbound.ProtocolReverseHTTP:
		if inbound.WhichProtocol() == legacyconfig.Inbound_Protocol_not_set_case {
			inbound.SetReverseHttp(&legacyconfig.ReverseHttp{})
		}
	case contractinbound.ProtocolReverseTCP:
		if inbound.WhichProtocol() == legacyconfig.Inbound_Protocol_not_set_case {
			inbound.SetReverseTcp(&legacyconfig.ReverseTcp{})
		}
	case contractinbound.ProtocolNone:
		if inbound.WhichProtocol() == legacyconfig.Inbound_Protocol_not_set_case {
			inbound.SetNone(&legacyconfig.Empty{})
		}
	case "tcpudp":
		if inbound.WhichNetwork() == legacyconfig.Inbound_Network_not_set_case {
			inbound.SetTcpudp(&legacyconfig.Tcpudp{})
		}
	case contractinbound.NetworkQUIC:
		if inbound.WhichNetwork() == legacyconfig.Inbound_Network_not_set_case {
			inbound.SetQuic(&legacyconfig.Quic{})
		}
	case contractinbound.NetworkEmpty:
		if inbound.WhichNetwork() == legacyconfig.Inbound_Network_not_set_case {
			inbound.SetEmpty(&legacyconfig.Empty{})
		}
	}
}

func dropEmptyLegacyTransports(name string, inbound *legacyconfig.Inbound) []Warning {
	if inbound == nil {
		return nil
	}
	transports := inbound.GetTransport()
	if len(transports) == 0 {
		return nil
	}
	filtered := make([]*legacyconfig.Transport, 0, len(transports))
	var warnings []Warning
	for index, transport := range transports {
		if transport.WhichTransport() == legacyconfig.Transport_Transport_not_set_case {
			warnings = append(warnings, Warning{
				Entity:  name,
				Message: fmt.Sprintf("legacy inbound transport[%d] has no concrete object in SQLite; deferred to config.json recovery", index),
			})
			continue
		}
		filtered = append(filtered, transport)
	}
	inbound.SetTransport(filtered)
	return warnings
}

func loadMigrationMarker(ctx context.Context, db *sql.DB, key string) (string, error) {
	var value string
	err := db.QueryRowContext(ctx, `SELECT value FROM metadata WHERE key = ?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("query migration marker %s failed: %w", key, err)
	}
	return value, nil
}

func migrationCounts(ctx context.Context, db *sql.DB, legacyTable, contractTable string) (legacyCount int, contractCount int, err error) {
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+legacyTable).Scan(&legacyCount); err != nil {
		return 0, 0, fmt.Errorf("count legacy table %s failed: %w", legacyTable, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+contractTable).Scan(&contractCount); err != nil {
		return 0, 0, fmt.Errorf("count contract table %s failed: %w", contractTable, err)
	}
	return legacyCount, contractCount, nil
}

func markMigrationDone(ctx context.Context, execer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, key string) error {
	_, err := execer.ExecContext(ctx, `
		INSERT INTO metadata(key, value)
		VALUES (?, '1')
		ON CONFLICT(key) DO UPDATE SET value = excluded.value
	`, key)
	return err
}

func renumberRouteRules(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `
		SELECT name
		FROM route_rules_v2
		ORDER BY priority, name
	`)
	if err != nil {
		return fmt.Errorf("query route rules for renumber failed: %w", err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return fmt.Errorf("scan route rule for renumber failed: %w", err)
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate route rules for renumber failed: %w", err)
	}
	for i, name := range names {
		if _, err := tx.ExecContext(ctx, `UPDATE route_rules_v2 SET priority = ? WHERE name = ?`, -(i + 1), name); err != nil {
			return fmt.Errorf("stage route rule %q priority failed: %w", name, err)
		}
	}
	for i, name := range names {
		if _, err := tx.ExecContext(ctx, `UPDATE route_rules_v2 SET priority = ? WHERE name = ?`, i+1, name); err != nil {
			return fmt.Errorf("update route rule %q priority failed: %w", name, err)
		}
	}
	return nil
}
