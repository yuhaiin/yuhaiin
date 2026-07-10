package store

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	legacymigrate "github.com/Asutorufa/yuhaiin/pkg/legacy/migrate"
	"github.com/Asutorufa/yuhaiin/pkg/legacy/schema/api"
	pn "github.com/Asutorufa/yuhaiin/pkg/legacy/schema/node"
	"github.com/Asutorufa/yuhaiin/pkg/paths"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
	"github.com/Asutorufa/yuhaiin/pkg/utils/id"
	"github.com/Asutorufa/yuhaiin/pkg/utils/jsondb"
	"github.com/Asutorufa/yuhaiin/pkg/utils/set"
)

type SqliteNodeStore struct {
	path     string
	mu       sync.Mutex
	store    *storagesqlite.Store
	imported bool
}

const (
	selectedTCPNodeMetadataKey = "selected_tcp_node_v2"
	selectedUDPNodeMetadataKey = "selected_udp_node_v2"
)

func NewSqliteNodeStore(path string) *SqliteNodeStore {
	return &SqliteNodeStore{path: path}
}

func (s *SqliteNodeStore) Load() (*pn.Node, error) {
	ctx := context.Background()
	store, err := s.open(ctx)
	if err != nil {
		return nil, err
	}

	tx, err := store.DB().BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("begin sqlite node load transaction failed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	data, err := loadNodeDataTx(ctx, tx)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit sqlite node load transaction failed: %w", err)
	}

	return data, nil
}

func (s *SqliteNodeStore) Save(data *pn.Node) error {
	ctx := context.Background()
	store, err := s.open(ctx)
	if err != nil {
		return err
	}

	tx, err := store.DB().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin sqlite node save transaction failed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := saveNodeDataTx(ctx, tx, data); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit sqlite node save transaction failed: %w", err)
	}

	return nil
}

func (s *SqliteNodeStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.store == nil {
		return nil
	}
	err := s.store.Close()
	s.store = nil
	s.imported = false
	return err
}

func (s *SqliteNodeStore) open(ctx context.Context) (*storagesqlite.Store, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.store == nil {
		store, err := storagesqlite.Open(ctx, s.path)
		if err != nil {
			return nil, fmt.Errorf("open sqlite node store failed: %w", err)
		}
		s.store = store
	}

	if !s.imported {
		if err := s.ensureImported(ctx, s.store.DB()); err != nil {
			return nil, err
		}
		s.imported = true
	}
	return s.store, nil
}

func (s *SqliteNodeStore) withTx(ctx context.Context, f func(context.Context, *sql.Tx) error) error {
	store, err := s.open(ctx)
	if err != nil {
		return err
	}

	tx, err := store.DB().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin sqlite node transaction failed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := f(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit sqlite node transaction failed: %w", err)
	}
	return nil
}

func (s *SqliteNodeStore) SaveNodes(points ...*pn.Point) error {
	if len(points) == 0 {
		return nil
	}

	return s.withTx(context.Background(), func(ctx context.Context, tx *sql.Tx) error {
		for _, point := range points {
			if point.GetHash() == "" {
				hash, err := generateNodeHash(ctx, tx)
				if err != nil {
					return err
				}
				point.SetHash(hash)
			}

			if err := upsertNodeTx(ctx, tx, point, time.Now().Unix()); err != nil {
				return err
			}
		}

		return rebuildNodeFTS(ctx, tx)
	})
}

func (s *SqliteNodeStore) SaveContractNode(node contractnode.Node) error {
	return s.withTx(context.Background(), func(ctx context.Context, tx *sql.Tx) error {
		return plainstore.SaveNodeContract(ctx, tx, node, time.Now().Unix())
	})
}

func (s *SqliteNodeStore) ReplaceRemoteContractNodes(group string, nodes []contractnode.Node) error {
	return s.withTx(context.Background(), func(ctx context.Context, tx *sql.Tx) error {
		now := time.Now().Unix()
		if err := plainstore.DeleteRemoteNodeContracts(ctx, tx, group); err != nil {
			return err
		}
		for _, node := range nodes {
			node.Group = group
			node.Origin = "remote"
			if node.ID == "" {
				hash, err := generateContractNodeID(ctx, tx)
				if err != nil {
					return err
				}
				node.ID = hash
			}
			if err := plainstore.SaveNodeContract(ctx, tx, node, now); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *SqliteNodeStore) DeleteRemoteNodes(group string) error {
	return s.withTx(context.Background(), func(ctx context.Context, tx *sql.Tx) error {
		if err := deleteRemoteNodesTx(ctx, tx, group); err != nil {
			return err
		}

		return rebuildNodeFTS(ctx, tx)
	})
}

func (s *SqliteNodeStore) ReplaceRemoteNodes(group string, points ...*pn.Point) error {
	return s.withTx(context.Background(), func(ctx context.Context, tx *sql.Tx) error {
		if err := deleteRemoteNodesTx(ctx, tx, group); err != nil {
			return err
		}

		now := time.Now().Unix()
		for _, point := range points {
			point.SetGroup(group)
			point.SetOrigin(pn.Origin_remote)

			if point.GetHash() == "" {
				hash, err := generateNodeHash(ctx, tx)
				if err != nil {
					return err
				}
				point.SetHash(hash)
			}

			if err := upsertNodeTx(ctx, tx, point, now); err != nil {
				return err
			}
		}

		return rebuildNodeFTS(ctx, tx)
	})
}

func (s *SqliteNodeStore) DeleteNode(hash string) error {
	return s.withTx(context.Background(), func(ctx context.Context, tx *sql.Tx) error {
		if err := deleteNodeTx(ctx, tx, hash); err != nil {
			return err
		}
		return rebuildNodeFTS(ctx, tx)
	})
}

func (s *SqliteNodeStore) GetNode(hash string) (*pn.Point, bool, error) {
	ctx := context.Background()
	store, err := s.open(ctx)
	if err != nil {
		return nil, false, err
	}

	point, ok, err := getNodeTx(ctx, store.DB(), hash)
	return point, ok, err
}

func (s *SqliteNodeStore) GetContractNode(hash string) (contractnode.Node, bool, error) {
	ctx := context.Background()
	store, err := s.open(ctx)
	if err != nil {
		return contractnode.Node{}, false, err
	}

	return getContractNodeTx(ctx, store.DB(), hash)
}

func (s *SqliteNodeStore) ListContractNodes() ([]contractnode.Node, error) {
	ctx := context.Background()
	store, err := s.open(ctx)
	if err != nil {
		return nil, err
	}

	rows, err := store.DB().QueryContext(ctx, `
		SELECT data_json
		FROM nodes_v2
		ORDER BY group_name, name, id
	`)
	if err != nil {
		return nil, fmt.Errorf("query node contracts failed: %w", err)
	}
	defer rows.Close()

	var out []contractnode.Node
	for rows.Next() {
		var dataJSON string
		if err := rows.Scan(&dataJSON); err != nil {
			return nil, fmt.Errorf("scan node contract failed: %w", err)
		}
		var node contractnode.Node
		if err := json.Unmarshal([]byte(dataJSON), &node); err != nil {
			return nil, fmt.Errorf("decode node contract failed: %w", err)
		}
		if err := node.Validate(); err != nil {
			return nil, err
		}
		out = append(out, node)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate node contracts failed: %w", err)
	}
	return out, nil
}

func (s *SqliteNodeStore) GetNow(tcp bool) (*pn.Point, error) {
	ctx := context.Background()
	store, err := s.open(ctx)
	if err != nil {
		return nil, err
	}

	column := "selected_udp"
	if tcp {
		column = "selected_tcp"
	}

	var dataJSON string
	err = store.DB().QueryRowContext(ctx, `
		SELECT data_json
		FROM nodes
		WHERE `+column+` = 1
		LIMIT 1
	`).Scan(&dataJSON)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return &pn.Point{}, nil
	case err != nil:
		return nil, fmt.Errorf("query selected node failed: %w", err)
	}

	point := &pn.Point{}
	if err := decodeNodeJSON(dataJSON, point); err != nil {
		return nil, fmt.Errorf("decode selected node failed: %w", err)
	}
	return point, nil
}

func (s *SqliteNodeStore) GetContractNow(tcp bool) (contractnode.Node, bool, error) {
	ctx := context.Background()
	store, err := s.open(ctx)
	if err != nil {
		return contractnode.Node{}, false, err
	}

	key := selectedUDPNodeMetadataKey
	if tcp {
		key = selectedTCPNodeMetadataKey
	}
	if hash, err := loadNodeMetadata(ctx, store.DB(), key); err != nil {
		return contractnode.Node{}, false, err
	} else if hash != "" {
		node, ok, err := getContractNodeTx(ctx, store.DB(), hash)
		if err != nil || ok {
			return node, ok, err
		}
	}

	column := "selected_udp"
	if tcp {
		column = "selected_tcp"
	}

	var hash string
	err = store.DB().QueryRowContext(ctx, `
		SELECT hash
		FROM nodes
		WHERE `+column+` = 1
		LIMIT 1
	`).Scan(&hash)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return contractnode.Node{}, false, nil
	case err != nil:
		return contractnode.Node{}, false, fmt.Errorf("query selected node contract id failed: %w", err)
	}
	return getContractNodeTx(ctx, store.DB(), hash)
}

func (s *SqliteNodeStore) UsePoint(hash string) error {
	return s.withTx(context.Background(), func(ctx context.Context, tx *sql.Tx) error {
		legacyExists, err := nodeExists(ctx, tx, hash)
		if err != nil {
			return err
		}
		contractExists, err := contractNodeExists(ctx, tx, hash)
		if err != nil {
			return err
		}
		if !legacyExists && !contractExists {
			return errors.New("node not found")
		}

		if err := updateNodeMetadataTx(ctx, tx, map[string]string{
			selectedTCPNodeMetadataKey: hash,
			selectedUDPNodeMetadataKey: hash,
		}); err != nil {
			return err
		}

		for _, column := range []string{"selected_tcp", "selected_udp"} {
			if _, err := tx.ExecContext(ctx, "UPDATE nodes SET "+column+" = 0 WHERE "+column+" = 1"); err != nil {
				return fmt.Errorf("clear %s failed: %w", column, err)
			}
			if legacyExists {
				if _, err := tx.ExecContext(ctx, "UPDATE nodes SET "+column+" = 1 WHERE hash = ?", hash); err != nil {
					return fmt.Errorf("set %s failed: %w", column, err)
				}
			}
		}
		return nil
	})
}

func (s *SqliteNodeStore) GetGroups() (map[string][]*api.NodesResponse_Node, error) {
	ctx := context.Background()
	store, err := s.open(ctx)
	if err != nil {
		return nil, err
	}

	rows, err := store.DB().QueryContext(ctx, `
		SELECT hash, name, group_name
		FROM nodes
		ORDER BY group_name, name
	`)
	if err != nil {
		return nil, fmt.Errorf("query node groups failed: %w", err)
	}
	defer rows.Close()

	groups := map[string][]*api.NodesResponse_Node{}
	for rows.Next() {
		var hash, name, group string
		if err := rows.Scan(&hash, &name, &group); err != nil {
			return nil, fmt.Errorf("scan node group failed: %w", err)
		}
		if group == "" {
			group = "unknown"
		}
		groups[group] = append(groups[group], api.NodesResponse_Node_builder{
			Hash: new(hash),
			Name: new(name),
		}.Build())
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate node groups failed: %w", err)
	}
	return groups, nil
}

func (s *SqliteNodeStore) AddTag(tag string, typ pn.TagType, hash string) error {
	return s.withTx(context.Background(), func(ctx context.Context, tx *sql.Tx) error {
		targetKind := "node"
		switch typ {
		case pn.TagType_node:
			ok, err := nodeExists(ctx, tx, hash)
			if err != nil {
				return err
			}
			if !ok {
				return nil
			}
		case pn.TagType_mirror:
			if tag == hash {
				return nil
			}
			targetKind = "tag"
		}

		if _, err := tx.ExecContext(ctx, `
			INSERT INTO node_tags(tag_name, target_kind, target_id, updated_at)
			VALUES (?, ?, ?, ?)
			ON CONFLICT(tag_name, target_kind, target_id) DO UPDATE SET updated_at = excluded.updated_at
		`, tag, targetKind, hash, time.Now().Unix()); err != nil {
			return fmt.Errorf("insert node tag failed: %w", err)
		}
		return nil
	})
}

func (s *SqliteNodeStore) DeleteTag(tag string) error {
	return s.withTx(context.Background(), func(ctx context.Context, tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM node_tags WHERE tag_name = ?`, tag); err != nil {
			return fmt.Errorf("delete node tag %q failed: %w", tag, err)
		}
		return nil
	})
}

func (s *SqliteNodeStore) GetTag(tag string) (*pn.Tags, bool, error) {
	ctx := context.Background()
	store, err := s.open(ctx)
	if err != nil {
		return nil, false, err
	}

	tags, err := loadOneTag(ctx, store.DB(), tag)
	if err != nil {
		return nil, false, err
	}
	return tags, tags != nil, nil
}

func (s *SqliteNodeStore) GetTags() (map[string]*pn.Tags, error) {
	ctx := context.Background()
	store, err := s.open(ctx)
	if err != nil {
		return nil, err
	}

	return loadTags(ctx, store.DB())
}

func (s *SqliteNodeStore) UsingPoints() (*set.Set[string], error) {
	ctx := context.Background()
	store, err := s.open(ctx)
	if err != nil {
		return nil, err
	}

	used := set.NewSet[string]()
	for _, key := range []string{selectedTCPNodeMetadataKey, selectedUDPNodeMetadataKey} {
		hash, err := loadNodeMetadata(ctx, store.DB(), key)
		if err != nil {
			return nil, err
		}
		if hash != "" {
			used.Push(hash)
		}
	}
	rows, err := store.DB().QueryContext(ctx, `
		SELECT hash
		FROM nodes
		WHERE selected_tcp = 1 OR selected_udp = 1
		UNION
		SELECT target_id
		FROM node_tags
		WHERE target_kind = 'node'
	`)
	if err != nil {
		return nil, fmt.Errorf("query using points failed: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			return nil, fmt.Errorf("scan using point failed: %w", err)
		}
		used.Push(hash)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate using points failed: %w", err)
	}
	return used, nil
}

func (s *SqliteNodeStore) GetContractTag(tag string) (string, []string, bool, error) {
	ctx := context.Background()
	store, err := s.open(ctx)
	if err != nil {
		return "", nil, false, err
	}
	rows, err := store.DB().QueryContext(ctx, `
		SELECT target_kind, target_id
		FROM node_tags
		WHERE tag_name = ?
		ORDER BY target_kind, target_id
	`, tag)
	if err != nil {
		return "", nil, false, fmt.Errorf("query node tag %q failed: %w", tag, err)
	}
	defer rows.Close()
	kind := "node"
	var targets []string
	for rows.Next() {
		var targetKind, targetID string
		if err := rows.Scan(&targetKind, &targetID); err != nil {
			return "", nil, false, fmt.Errorf("scan node tag %q failed: %w", tag, err)
		}
		if targetKind == "tag" {
			kind = "mirror"
		}
		targets = append(targets, targetID)
	}
	if err := rows.Err(); err != nil {
		return "", nil, false, fmt.Errorf("iterate node tag %q failed: %w", tag, err)
	}
	return kind, targets, len(targets) > 0, nil
}

func (s *SqliteNodeStore) UsingContractPoints() (*set.Set[string], error) {
	ctx := context.Background()
	store, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	used := set.NewSet[string]()
	for _, key := range []string{selectedTCPNodeMetadataKey, selectedUDPNodeMetadataKey} {
		hash, err := loadNodeMetadata(ctx, store.DB(), key)
		if err != nil {
			return nil, err
		}
		if hash != "" {
			used.Push(hash)
		}
	}
	rows, err := store.DB().QueryContext(ctx, `
		SELECT target_id
		FROM node_tags
		WHERE target_kind = 'node'
	`)
	if err != nil {
		return nil, fmt.Errorf("query using contract nodes failed: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			return nil, fmt.Errorf("scan using contract node failed: %w", err)
		}
		used.Push(hash)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate using contract nodes failed: %w", err)
	}
	return used, nil
}

func (s *SqliteNodeStore) SaveLinks(links ...*pn.Link) error {
	if len(links) == 0 {
		return nil
	}
	return s.withTx(context.Background(), func(ctx context.Context, tx *sql.Tx) error {
		now := time.Now().Unix()
		for _, link := range links {
			dataJSON, err := encodeNodeJSON(link)
			if err != nil {
				return fmt.Errorf("encode subscription %q failed: %w", link.GetName(), err)
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO subscriptions(name, updated_at, data_json)
				VALUES (?, ?, ?)
				ON CONFLICT(name) DO UPDATE SET
					updated_at = excluded.updated_at,
					data_json = excluded.data_json
			`, link.GetName(), now, dataJSON); err != nil {
				return fmt.Errorf("upsert subscription %q failed: %w", link.GetName(), err)
			}
		}
		return nil
	})
}

func (s *SqliteNodeStore) DeleteLinks(names ...string) error {
	if len(names) == 0 {
		return nil
	}
	return s.withTx(context.Background(), func(ctx context.Context, tx *sql.Tx) error {
		for _, name := range names {
			if _, err := tx.ExecContext(ctx, `DELETE FROM subscriptions WHERE name = ?`, name); err != nil {
				return fmt.Errorf("delete subscription %q failed: %w", name, err)
			}
		}
		return nil
	})
}

func (s *SqliteNodeStore) GetLinks() (map[string]*pn.Link, error) {
	ctx := context.Background()
	store, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	return loadLinks(ctx, store.DB())
}

func (s *SqliteNodeStore) GetLink(name string) (*pn.Link, bool, error) {
	ctx := context.Background()
	store, err := s.open(ctx)
	if err != nil {
		return nil, false, err
	}

	var dataJSON string
	err = store.DB().QueryRowContext(ctx, `
		SELECT data_json
		FROM subscriptions
		WHERE name = ?
	`, name).Scan(&dataJSON)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, false, nil
	case err != nil:
		return nil, false, fmt.Errorf("query subscription %q failed: %w", name, err)
	}

	link := &pn.Link{}
	if err := decodeNodeJSON(dataJSON, link); err != nil {
		return nil, false, fmt.Errorf("decode subscription %q failed: %w", name, err)
	}
	return link, true, nil
}

func (s *SqliteNodeStore) SavePublish(name string, publish *pn.Publish) error {
	return s.withTx(context.Background(), func(ctx context.Context, tx *sql.Tx) error {
		dataJSON, err := encodeNodeJSON(publish)
		if err != nil {
			return fmt.Errorf("encode publish %q failed: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO publishes(name, updated_at, data_json)
			VALUES (?, ?, ?)
			ON CONFLICT(name) DO UPDATE SET
				updated_at = excluded.updated_at,
				data_json = excluded.data_json
		`, name, time.Now().Unix(), dataJSON); err != nil {
			return fmt.Errorf("upsert publish %q failed: %w", name, err)
		}
		return nil
	})
}

func (s *SqliteNodeStore) DeletePublish(name string) error {
	return s.withTx(context.Background(), func(ctx context.Context, tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM publishes WHERE name = ?`, name); err != nil {
			return fmt.Errorf("delete publish %q failed: %w", name, err)
		}
		return nil
	})
}

func (s *SqliteNodeStore) GetPublishes() (map[string]*pn.Publish, error) {
	ctx := context.Background()
	store, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	return loadPublishes(ctx, store.DB())
}

func (s *SqliteNodeStore) Publish(name, path, password string) ([]*pn.Point, error) {
	ctx := context.Background()
	store, err := s.open(ctx)
	if err != nil {
		return nil, err
	}

	var dataJSON string
	err = store.DB().QueryRowContext(ctx, `
		SELECT data_json
		FROM publishes
		WHERE name = ?
	`, name).Scan(&dataJSON)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("query publish %q failed: %w", name, err)
	}

	publish := &pn.Publish{}
	if err := decodeNodeJSON(dataJSON, publish); err != nil {
		return nil, fmt.Errorf("decode publish %q failed: %w", name, err)
	}
	if publish.GetPath() != path {
		return nil, nil
	}
	if subtle.ConstantTimeCompare([]byte(publish.GetPassword()), []byte(password)) != 1 {
		return nil, nil
	}

	points := make([]*pn.Point, 0, len(publish.GetPoints()))
	for _, hash := range publish.GetPoints() {
		point, ok, err := getNodeTx(ctx, store.DB(), hash)
		if err != nil {
			return nil, err
		}
		if ok {
			points = append(points, point)
		}
	}
	return points, nil
}

func (s *SqliteNodeStore) ensureImported(ctx context.Context, db *sql.DB) error {
	done, err := loadNodeMetadata(ctx, db, "legacy_node_import_done")
	if err != nil {
		return err
	}
	if done == "1" {
		return syncAllPlainNodeContracts(ctx, db, time.Now().Unix())
	}

	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM nodes`).Scan(&count); err != nil {
		return fmt.Errorf("count nodes failed: %w", err)
	}
	if count > 0 {
		if err := syncAllPlainNodeContracts(ctx, db, time.Now().Unix()); err != nil {
			return err
		}
		return updateNodeMetadata(ctx, db, map[string]string{
			"legacy_node_import_done":   "1",
			"legacy_node_import_source": "existing_sqlite",
		})
	}

	data := defaultNodeData()
	source := "defaults"

	legacyPath := paths.PathGenerator.Node(filepath.Dir(s.path))
	if fileExists(legacyPath) {
		data = jsondb.Open(legacyPath, defaultNodeData()).Data
		source = "node.json"
	}
	normalizeNodeData(data)

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin sqlite legacy node import transaction failed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := saveNodeDataTx(ctx, tx, data); err != nil {
		return err
	}
	if err := updateNodeMetadataTx(ctx, tx, map[string]string{
		"legacy_node_import_done":   "1",
		"legacy_node_import_source": source,
	}); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit sqlite legacy node import transaction failed: %w", err)
	}

	return nil
}

func loadNodeDataTx(ctx context.Context, tx *sql.Tx) (*pn.Node, error) {
	data := defaultNodeData()
	normalizeNodeData(data)

	data.GetManager().SetNodes(map[string]*pn.Point{})
	data.GetManager().SetTags(map[string]*pn.Tags{})
	data.GetManager().SetPublishes(map[string]*pn.Publish{})
	data.SetLinks(map[string]*pn.Link{})

	rows, err := tx.QueryContext(ctx, `
		SELECT hash, selected_tcp, selected_udp, data_json
		FROM nodes
		ORDER BY id
	`)
	if err != nil {
		return nil, fmt.Errorf("query nodes failed: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var hash, dataJSON string
		var selectedTCP, selectedUDP int
		if err := rows.Scan(&hash, &selectedTCP, &selectedUDP, &dataJSON); err != nil {
			return nil, fmt.Errorf("scan node failed: %w", err)
		}

		point := &pn.Point{}
		if err := decodeNodeJSON(dataJSON, point); err != nil {
			return nil, fmt.Errorf("decode node %q failed: %w", hash, err)
		}
		point.SetHash(hash)
		data.GetManager().GetNodes()[hash] = point

		if selectedTCP != 0 {
			data.SetTcp(point)
		}
		if selectedUDP != 0 {
			data.SetUdp(point)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate nodes failed: %w", err)
	}

	tagRows, err := tx.QueryContext(ctx, `
		SELECT tag_name, target_kind, target_id
		FROM node_tags
		ORDER BY tag_name, target_kind, target_id
	`)
	if err != nil {
		return nil, fmt.Errorf("query node_tags failed: %w", err)
	}
	defer tagRows.Close()

	for tagRows.Next() {
		var tagName, targetKind, targetID string
		if err := tagRows.Scan(&tagName, &targetKind, &targetID); err != nil {
			return nil, fmt.Errorf("scan node tag failed: %w", err)
		}

		tag := data.GetManager().GetTags()[tagName]
		if tag == nil {
			tag = pn.Tags_builder{
				Tag:  new(tagName),
				Type: pn.TagType_node.Enum(),
			}.Build()
			data.GetManager().GetTags()[tagName] = tag
		}

		if targetKind == "tag" {
			tag.SetType(pn.TagType_mirror)
		}
		tag.SetHash(append(tag.GetHash(), targetID))
	}
	if err := tagRows.Err(); err != nil {
		return nil, fmt.Errorf("iterate node_tags failed: %w", err)
	}

	linkRows, err := tx.QueryContext(ctx, `
		SELECT name, data_json
		FROM subscriptions
		ORDER BY name
	`)
	if err != nil {
		return nil, fmt.Errorf("query subscriptions failed: %w", err)
	}
	defer linkRows.Close()

	for linkRows.Next() {
		var name, dataJSON string
		if err := linkRows.Scan(&name, &dataJSON); err != nil {
			return nil, fmt.Errorf("scan subscription failed: %w", err)
		}
		link := &pn.Link{}
		if err := decodeNodeJSON(dataJSON, link); err != nil {
			return nil, fmt.Errorf("decode subscription %q failed: %w", name, err)
		}
		data.GetLinks()[name] = link
	}
	if err := linkRows.Err(); err != nil {
		return nil, fmt.Errorf("iterate subscriptions failed: %w", err)
	}

	publishRows, err := tx.QueryContext(ctx, `
		SELECT name, data_json
		FROM publishes
		ORDER BY name
	`)
	if err != nil {
		return nil, fmt.Errorf("query publishes failed: %w", err)
	}
	defer publishRows.Close()

	for publishRows.Next() {
		var name, dataJSON string
		if err := publishRows.Scan(&name, &dataJSON); err != nil {
			return nil, fmt.Errorf("scan publish failed: %w", err)
		}
		publish := &pn.Publish{}
		if err := decodeNodeJSON(dataJSON, publish); err != nil {
			return nil, fmt.Errorf("decode publish %q failed: %w", name, err)
		}
		data.GetManager().GetPublishes()[name] = publish
	}
	if err := publishRows.Err(); err != nil {
		return nil, fmt.Errorf("iterate publishes failed: %w", err)
	}

	normalizeNodeData(data)
	return data, nil
}

func saveNodeDataTx(ctx context.Context, tx *sql.Tx, data *pn.Node) error {
	normalizeNodeData(data)

	for _, table := range []string{"node_tags", "subscriptions", "publishes", "nodes", "nodes_v2"} {
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+table); err != nil {
			return fmt.Errorf("clear %s failed: %w", table, err)
		}
	}

	now := time.Now().Unix()
	nodeKeys := slices.Collect(maps.Keys(data.GetManager().GetNodes()))
	slices.Sort(nodeKeys)
	for _, hash := range nodeKeys {
		point := data.GetManager().GetNodes()[hash]
		if point.GetHash() == "" {
			point.SetHash(hash)
		}

		dataJSON, err := encodeNodeJSON(point)
		if err != nil {
			return fmt.Errorf("encode node %q failed: %w", hash, err)
		}

		if _, err := tx.ExecContext(ctx, `
			INSERT INTO nodes(hash, group_name, name, origin, selected_tcp, selected_udp, search_text, updated_at, data_json)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, hash, point.GetGroup(), point.GetName(), int(point.GetOrigin()), boolToInt(nodeMatches(data.GetTcp(), point)), boolToInt(nodeMatches(data.GetUdp(), point)), nodeSearchText(point, dataJSON), now, dataJSON); err != nil {
			return fmt.Errorf("insert node %q failed: %w", hash, err)
		}
		if err := syncPlainNodeContractTx(ctx, tx, point, now); err != nil {
			return err
		}
	}

	tagKeys := slices.Collect(maps.Keys(data.GetManager().GetTags()))
	slices.Sort(tagKeys)
	for _, tagName := range tagKeys {
		tag := data.GetManager().GetTags()[tagName]
		targetKind := "node"
		if tag.GetType() == pn.TagType_mirror {
			targetKind = "tag"
		}

		for _, targetID := range tag.GetHash() {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO node_tags(tag_name, target_kind, target_id, updated_at)
				VALUES (?, ?, ?, ?)
			`, tagName, targetKind, targetID, now); err != nil {
				return fmt.Errorf("insert node tag %q -> %q failed: %w", tagName, targetID, err)
			}
		}
	}

	linkKeys := slices.Collect(maps.Keys(data.GetLinks()))
	slices.Sort(linkKeys)
	for _, name := range linkKeys {
		link := data.GetLinks()[name]
		dataJSON, err := encodeNodeJSON(link)
		if err != nil {
			return fmt.Errorf("encode subscription %q failed: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO subscriptions(name, updated_at, data_json)
			VALUES (?, ?, ?)
		`, name, now, dataJSON); err != nil {
			return fmt.Errorf("insert subscription %q failed: %w", name, err)
		}
	}

	publishKeys := slices.Collect(maps.Keys(data.GetManager().GetPublishes()))
	slices.Sort(publishKeys)
	for _, name := range publishKeys {
		publish := data.GetManager().GetPublishes()[name]
		dataJSON, err := encodeNodeJSON(publish)
		if err != nil {
			return fmt.Errorf("encode publish %q failed: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO publishes(name, updated_at, data_json)
			VALUES (?, ?, ?)
		`, name, now, dataJSON); err != nil {
			return fmt.Errorf("insert publish %q failed: %w", name, err)
		}
	}

	if _, err := tx.ExecContext(ctx, `INSERT INTO nodes_fts(nodes_fts) VALUES ('rebuild')`); err != nil {
		return fmt.Errorf("rebuild nodes_fts failed: %w", err)
	}

	return nil
}

func syncAllPlainNodeContracts(ctx context.Context, db *sql.DB, now int64) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin plain node contract sync transaction failed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `DELETE FROM nodes_v2`); err != nil {
		return fmt.Errorf("clear node contracts failed: %w", err)
	}

	rows, err := tx.QueryContext(ctx, `
		SELECT hash, data_json
		FROM nodes
		ORDER BY id
	`)
	if err != nil {
		return fmt.Errorf("query legacy nodes for plain sync failed: %w", err)
	}

	var points []*pn.Point
	for rows.Next() {
		var hash, dataJSON string
		if err := rows.Scan(&hash, &dataJSON); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan legacy node for plain sync failed: %w", err)
		}
		point := &pn.Point{}
		if err := decodeNodeJSON(dataJSON, point); err != nil {
			_ = rows.Close()
			return fmt.Errorf("decode legacy node %q for plain sync failed: %w", hash, err)
		}
		point.SetHash(hash)
		points = append(points, point)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("iterate legacy nodes for plain sync failed: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close legacy node rows for plain sync failed: %w", err)
	}

	for _, point := range points {
		if err := syncPlainNodeContractTx(ctx, tx, point, now); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit plain node contract sync transaction failed: %w", err)
	}
	return nil
}

func getContractNodeTx(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, hash string) (contractnode.Node, bool, error) {
	var dataJSON string
	err := q.QueryRowContext(ctx, `
		SELECT data_json
		FROM nodes_v2
		WHERE id = ?
	`, hash).Scan(&dataJSON)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return contractnode.Node{}, false, nil
	case err != nil:
		return contractnode.Node{}, false, fmt.Errorf("query node contract %q failed: %w", hash, err)
	}
	var node contractnode.Node
	if err := json.Unmarshal([]byte(dataJSON), &node); err != nil {
		return contractnode.Node{}, false, fmt.Errorf("decode node contract %q failed: %w", hash, err)
	}
	if err := node.Validate(); err != nil {
		return contractnode.Node{}, false, err
	}
	return node, true, nil
}

func syncPlainNodeContractTx(ctx context.Context, tx *sql.Tx, point *pn.Point, now int64) error {
	return legacymigrate.SyncLegacyNodeContract(ctx, tx, point, now)
}

func generateNodeHash(ctx context.Context, tx *sql.Tx) (string, error) {
	for {
		hash := id.GenerateUUID().String()
		ok, err := nodeExists(ctx, tx, hash)
		if err != nil {
			return "", err
		}
		if !ok {
			return hash, nil
		}
	}
}

func generateContractNodeID(ctx context.Context, tx *sql.Tx) (string, error) {
	for {
		hash := id.GenerateUUID().String()
		ok, err := contractNodeExists(ctx, tx, hash)
		if err != nil {
			return "", err
		}
		if !ok {
			return hash, nil
		}
	}
}

func upsertNodeTx(ctx context.Context, tx *sql.Tx, point *pn.Point, now int64) error {
	dataJSON, err := encodeNodeJSON(point)
	if err != nil {
		return fmt.Errorf("encode node %q failed: %w", point.GetHash(), err)
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO nodes(hash, group_name, name, origin, search_text, updated_at, data_json)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(hash) DO UPDATE SET
			group_name = excluded.group_name,
			name = excluded.name,
			origin = excluded.origin,
			search_text = excluded.search_text,
			updated_at = excluded.updated_at,
			data_json = excluded.data_json
	`, point.GetHash(), point.GetGroup(), point.GetName(), int(point.GetOrigin()), nodeSearchText(point, dataJSON), now, dataJSON); err != nil {
		return fmt.Errorf("upsert node %q failed: %w", point.GetHash(), err)
	}
	if err := syncPlainNodeContractTx(ctx, tx, point, now); err != nil {
		return err
	}
	return nil
}

func deleteNodeTx(ctx context.Context, tx *sql.Tx, hash string) error {
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM node_tags
		WHERE target_kind = 'node' AND target_id = ?
	`, hash); err != nil {
		return fmt.Errorf("delete node tag members for %q failed: %w", hash, err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM nodes WHERE hash = ?`, hash); err != nil {
		return fmt.Errorf("delete node %q failed: %w", hash, err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM nodes_v2 WHERE id = ?`, hash); err != nil {
		return fmt.Errorf("delete node contract %q failed: %w", hash, err)
	}
	return nil
}

func deleteRemoteNodesTx(ctx context.Context, tx *sql.Tx, group string) error {
	rows, err := tx.QueryContext(ctx, `
		SELECT hash
		FROM nodes
		WHERE group_name = ? AND origin = ?
	`, group, int(pn.Origin_remote))
	if err != nil {
		return fmt.Errorf("query remote nodes failed: %w", err)
	}
	defer rows.Close()

	var hashes []string
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			return fmt.Errorf("scan remote node hash failed: %w", err)
		}
		hashes = append(hashes, hash)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate remote node hashes failed: %w", err)
	}

	for _, hash := range hashes {
		if err := deleteNodeTx(ctx, tx, hash); err != nil {
			return err
		}
	}
	return nil
}

func rebuildNodeFTS(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `INSERT INTO nodes_fts(nodes_fts) VALUES ('rebuild')`); err != nil {
		return fmt.Errorf("rebuild nodes_fts failed: %w", err)
	}
	return nil
}

func nodeExists(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, hash string) (bool, error) {
	var exists int
	if err := q.QueryRowContext(ctx, `SELECT 1 FROM nodes WHERE hash = ?`, hash).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("query node %q existence failed: %w", hash, err)
	}
	return true, nil
}

func contractNodeExists(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, hash string) (bool, error) {
	var exists int
	if err := q.QueryRowContext(ctx, `SELECT 1 FROM nodes_v2 WHERE id = ?`, hash).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("query node contract %q existence failed: %w", hash, err)
	}
	return true, nil
}

func getNodeTx(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, hash string) (*pn.Point, bool, error) {
	var dataJSON string
	err := q.QueryRowContext(ctx, `
		SELECT data_json
		FROM nodes
		WHERE hash = ?
	`, hash).Scan(&dataJSON)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, false, nil
	case err != nil:
		return nil, false, fmt.Errorf("query node %q failed: %w", hash, err)
	}

	point := &pn.Point{}
	if err := decodeNodeJSON(dataJSON, point); err != nil {
		return nil, false, fmt.Errorf("decode node %q failed: %w", hash, err)
	}
	point.SetHash(hash)
	return point, true, nil
}

func loadOneTag(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, tagName string) (*pn.Tags, error) {
	tags, err := loadTagsWhere(ctx, q, `WHERE tag_name = ?`, tagName)
	if err != nil {
		return nil, err
	}
	return tags[tagName], nil
}

func loadTags(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) (map[string]*pn.Tags, error) {
	return loadTagsWhere(ctx, q, ``, nil)
}

func loadTagsWhere(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, where string, arg any) (map[string]*pn.Tags, error) {
	query := `
		SELECT tag_name, target_kind, target_id
		FROM node_tags
	` + where + `
		ORDER BY tag_name, target_kind, target_id
	`
	var rows *sql.Rows
	var err error
	if arg == nil {
		rows, err = q.QueryContext(ctx, query)
	} else {
		rows, err = q.QueryContext(ctx, query, arg)
	}
	if err != nil {
		return nil, fmt.Errorf("query node tags failed: %w", err)
	}
	defer rows.Close()

	tags := map[string]*pn.Tags{}
	for rows.Next() {
		var tagName, targetKind, targetID string
		if err := rows.Scan(&tagName, &targetKind, &targetID); err != nil {
			return nil, fmt.Errorf("scan node tag failed: %w", err)
		}
		tag := tags[tagName]
		if tag == nil {
			tag = pn.Tags_builder{
				Tag:  new(tagName),
				Type: pn.TagType_node.Enum(),
			}.Build()
			tags[tagName] = tag
		}
		if targetKind == "tag" {
			tag.SetType(pn.TagType_mirror)
		}
		tag.SetHash(append(tag.GetHash(), targetID))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate node tags failed: %w", err)
	}
	return tags, nil
}

func loadLinks(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) (map[string]*pn.Link, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT name, data_json
		FROM subscriptions
		ORDER BY name
	`)
	if err != nil {
		return nil, fmt.Errorf("query subscriptions failed: %w", err)
	}
	defer rows.Close()

	links := map[string]*pn.Link{}
	for rows.Next() {
		var name, dataJSON string
		if err := rows.Scan(&name, &dataJSON); err != nil {
			return nil, fmt.Errorf("scan subscription failed: %w", err)
		}
		link := &pn.Link{}
		if err := decodeNodeJSON(dataJSON, link); err != nil {
			return nil, fmt.Errorf("decode subscription %q failed: %w", name, err)
		}
		links[name] = link
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate subscriptions failed: %w", err)
	}
	return links, nil
}

func loadPublishes(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) (map[string]*pn.Publish, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT name, data_json
		FROM publishes
		ORDER BY name
	`)
	if err != nil {
		return nil, fmt.Errorf("query publishes failed: %w", err)
	}
	defer rows.Close()

	publishes := map[string]*pn.Publish{}
	for rows.Next() {
		var name, dataJSON string
		if err := rows.Scan(&name, &dataJSON); err != nil {
			return nil, fmt.Errorf("scan publish failed: %w", err)
		}
		publish := &pn.Publish{}
		if err := decodeNodeJSON(dataJSON, publish); err != nil {
			return nil, fmt.Errorf("decode publish %q failed: %w", name, err)
		}
		publishes[name] = publish
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate publishes failed: %w", err)
	}
	return publishes, nil
}

func nodeMatches(selected, point *pn.Point) bool {
	if selected == nil || point == nil {
		return false
	}
	return selected.GetHash() == point.GetHash()
}

func nodeSearchText(point *pn.Point, dataJSON string) string {
	return strings.Join([]string{
		point.GetName(),
		point.GetGroup(),
		point.GetHash(),
		dataJSON,
	}, "\n")
}

func encodeNodeJSON(msg any) (string, error) {
	data, err := json.Marshal(msg)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func decodeNodeJSON(data string, msg any) error {
	return json.Unmarshal([]byte(data), msg)
}

func loadNodeMetadata(ctx context.Context, queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, key string) (string, error) {
	var value string
	err := queryer.QueryRowContext(ctx, `SELECT value FROM metadata WHERE key = ?`, key).Scan(&value)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return "", nil
	case err != nil:
		return "", fmt.Errorf("load metadata %q failed: %w", key, err)
	default:
		return value, nil
	}
}

func updateNodeMetadata(ctx context.Context, db *sql.DB, values map[string]string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin node metadata transaction failed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := updateNodeMetadataTx(ctx, tx, values); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit node metadata transaction failed: %w", err)
	}
	return nil
}

func updateNodeMetadataTx(ctx context.Context, tx *sql.Tx, values map[string]string) error {
	keys := slices.Collect(maps.Keys(values))
	slices.Sort(keys)
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
