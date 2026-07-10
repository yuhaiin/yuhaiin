package migrate

import (
	"context"
	"database/sql"
	json "encoding/json/v2"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	legacynode "github.com/Asutorufa/yuhaiin/pkg/legacy/schema/node"
	"github.com/Asutorufa/yuhaiin/pkg/paths"
	"github.com/Asutorufa/yuhaiin/pkg/utils/jsondb"
)

func ImportLegacyNodesFromJSON(ctx context.Context, db *sql.DB, dir string, updatedAt int64) error {
	done, err := loadMigrationMarker(ctx, db, "legacy_node_import_done")
	if err != nil {
		return err
	}
	if done == "1" {
		return nil
	}

	legacyCount, err := tableCount(ctx, db, "nodes")
	if err != nil {
		return err
	}
	if legacyCount > 0 {
		return updateNodeImportMetadata(ctx, db, "existing_sqlite", false)
	}

	contractCount, err := tableCount(ctx, db, "nodes_v2")
	if err != nil {
		return err
	}
	if contractCount > 0 {
		return updateNodeImportMetadata(ctx, db, "existing_plain", true)
	}

	data := defaultLegacyNodeData()
	source := "defaults"
	nodePath := paths.PathGenerator.Node(dir)
	if fileExists(nodePath) {
		data = jsondb.Open(nodePath, defaultLegacyNodeData()).Data
		source = filepath.Base(nodePath)
	}
	normalizeLegacyNodeData(data)

	if updatedAt == 0 {
		updatedAt = time.Now().Unix()
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin legacy node json import transaction failed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := saveLegacyNodeDataTx(ctx, tx, data, updatedAt); err != nil {
		return err
	}
	if err := updateNodeImportMetadataTx(ctx, tx, source, false); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit legacy node json import transaction failed: %w", err)
	}
	return nil
}

func saveLegacyNodeDataTx(ctx context.Context, tx *sql.Tx, data *legacynode.Node, updatedAt int64) error {
	normalizeLegacyNodeData(data)
	for _, table := range []string{"node_tags", "subscriptions", "publishes", "nodes"} {
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+table); err != nil {
			return fmt.Errorf("clear %s before legacy node json import failed: %w", table, err)
		}
	}

	nodeIDs := sortedKeys(data.GetManager().GetNodes())
	for _, id := range nodeIDs {
		point := data.GetManager().GetNodes()[id]
		if point == nil {
			continue
		}
		if point.GetHash() == "" {
			point.SetHash(id)
		}
		dataJSON, err := encodeLegacyNodeJSON(point)
		if err != nil {
			return fmt.Errorf("encode legacy node %q failed: %w", id, err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO nodes(hash, group_name, name, origin, selected_tcp, selected_udp, search_text, updated_at, data_json)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, point.GetHash(), point.GetGroup(), point.GetName(), int(point.GetOrigin()),
			boolToInt(legacyNodeMatches(data.GetTcp(), point)),
			boolToInt(legacyNodeMatches(data.GetUdp(), point)),
			legacyNodeSearchText(point, dataJSON), updatedAt, dataJSON); err != nil {
			return fmt.Errorf("insert legacy node %q failed: %w", point.GetHash(), err)
		}
	}

	tagNames := sortedKeys(data.GetManager().GetTags())
	for _, tagName := range tagNames {
		tag := data.GetManager().GetTags()[tagName]
		if tag == nil {
			continue
		}
		targetKind := "node"
		if tag.GetType() == legacynode.TagType_mirror {
			targetKind = "tag"
		}
		for _, targetID := range tag.GetHash() {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO node_tags(tag_name, target_kind, target_id, updated_at)
				VALUES (?, ?, ?, ?)
			`, tagName, targetKind, targetID, updatedAt); err != nil {
				return fmt.Errorf("insert legacy node tag %q -> %q failed: %w", tagName, targetID, err)
			}
		}
	}

	linkNames := sortedKeys(data.GetLinks())
	for _, name := range linkNames {
		link := data.GetLinks()[name]
		if link == nil {
			continue
		}
		dataJSON, err := encodeLegacyNodeJSON(link)
		if err != nil {
			return fmt.Errorf("encode legacy subscription %q failed: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO subscriptions(name, updated_at, data_json)
			VALUES (?, ?, ?)
		`, name, updatedAt, dataJSON); err != nil {
			return fmt.Errorf("insert legacy subscription %q failed: %w", name, err)
		}
	}

	publishNames := sortedKeys(data.GetManager().GetPublishes())
	for _, name := range publishNames {
		publish := data.GetManager().GetPublishes()[name]
		if publish == nil {
			continue
		}
		dataJSON, err := encodeLegacyNodeJSON(publish)
		if err != nil {
			return fmt.Errorf("encode legacy publish %q failed: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO publishes(name, updated_at, data_json)
			VALUES (?, ?, ?)
		`, name, updatedAt, dataJSON); err != nil {
			return fmt.Errorf("insert legacy publish %q failed: %w", name, err)
		}
	}

	if _, err := tx.ExecContext(ctx, `INSERT INTO nodes_fts(nodes_fts) VALUES ('rebuild')`); err != nil {
		return fmt.Errorf("rebuild legacy nodes_fts failed: %w", err)
	}
	return nil
}

func updateNodeImportMetadata(ctx context.Context, db *sql.DB, source string, markPlainDone bool) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin legacy node import metadata transaction failed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := updateNodeImportMetadataTx(ctx, tx, source, markPlainDone); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit legacy node import metadata transaction failed: %w", err)
	}
	return nil
}

func updateNodeImportMetadataTx(ctx context.Context, tx *sql.Tx, source string, markPlainDone bool) error {
	values := map[string]string{
		"legacy_node_import_done":   "1",
		"legacy_node_import_source": source,
	}
	if markPlainDone {
		values["plain_nodes_migration_done"] = "1"
	}
	keys := sortedKeys(values)
	for _, key := range keys {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO metadata(key, value)
			VALUES (?, ?)
			ON CONFLICT(key) DO UPDATE SET value = excluded.value
		`, key, values[key]); err != nil {
			return fmt.Errorf("update metadata %q failed: %w", key, err)
		}
	}
	return nil
}

func tableCount(ctx context.Context, db *sql.DB, table string) (int, error) {
	var count int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&count); err != nil {
		return 0, fmt.Errorf("count %s failed: %w", table, err)
	}
	return count, nil
}

func defaultLegacyNodeData() *legacynode.Node {
	data := (&legacynode.Node_builder{
		Tcp:   &legacynode.Point{},
		Udp:   &legacynode.Point{},
		Links: map[string]*legacynode.Link{},
		Manager: (&legacynode.Manager_builder{
			Nodes:     map[string]*legacynode.Point{},
			Tags:      map[string]*legacynode.Tags{},
			Publishes: map[string]*legacynode.Publish{},
		}).Build(),
	}).Build()
	data.GetTcp().SetHash("inittcp")
	data.GetUdp().SetHash("initudp")
	return data
}

func normalizeLegacyNodeData(data *legacynode.Node) {
	if data.GetManager() == nil {
		data.SetManager(&legacynode.Manager{})
	}
	if data.GetManager().GetNodes() == nil {
		data.GetManager().SetNodes(map[string]*legacynode.Point{})
	}
	if data.GetManager().GetTags() == nil {
		data.GetManager().SetTags(map[string]*legacynode.Tags{})
	}
	if data.GetManager().GetPublishes() == nil {
		data.GetManager().SetPublishes(map[string]*legacynode.Publish{})
	}
	if data.GetLinks() == nil {
		data.SetLinks(map[string]*legacynode.Link{})
	}
	if data.GetTcp() == nil {
		data.SetTcp(&legacynode.Point{})
	}
	if data.GetUdp() == nil {
		data.SetUdp(&legacynode.Point{})
	}
}

func legacyNodeMatches(selected, point *legacynode.Point) bool {
	return selected != nil && point != nil && selected.GetHash() == point.GetHash()
}

func legacyNodeSearchText(point *legacynode.Point, dataJSON string) string {
	return strings.Join([]string{
		point.GetName(),
		point.GetGroup(),
		point.GetHash(),
		dataJSON,
	}, "\n")
}

func encodeLegacyNodeJSON(msg any) (string, error) {
	data, err := json.Marshal(msg)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
