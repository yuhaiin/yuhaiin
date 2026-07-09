package node

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
	"github.com/Asutorufa/yuhaiin/pkg/utils/set"
)

const (
	selectedTCPNodeMetadataKey = "selected_tcp_node_v2"
	selectedUDPNodeMetadataKey = "selected_udp_node_v2"
)

type SQLiteContractNodeStore struct {
	path  string
	mu    sync.Mutex
	store *storagesqlite.Store
	nodes *plainstore.NodeStore
}

func NewSQLiteContractNodeStore(path string) *SQLiteContractNodeStore {
	return &SQLiteContractNodeStore{path: path}
}

func (s *SQLiteContractNodeStore) open(ctx context.Context) (*storagesqlite.Store, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.store == nil {
		store, err := storagesqlite.Open(ctx, s.path)
		if err != nil {
			return nil, fmt.Errorf("open sqlite node contract store failed: %w", err)
		}
		s.store = store
		s.nodes = plainstore.NewNodeStore(store.DB())
	}
	return s.store, nil
}

func (s *SQLiteContractNodeStore) nodeStore(ctx context.Context) (*plainstore.NodeStore, error) {
	if _, err := s.open(ctx); err != nil {
		return nil, err
	}
	return s.nodes, nil
}

func (s *SQLiteContractNodeStore) SaveContractNode(node contractnode.Node) error {
	ctx := context.Background()
	nodes, err := s.nodeStore(ctx)
	if err != nil {
		return err
	}
	return nodes.Save(ctx, node, 0)
}

func (s *SQLiteContractNodeStore) ReplaceRemoteContractNodes(group string, nodes []contractnode.Node) error {
	ctx := context.Background()
	store, err := s.nodeStore(ctx)
	if err != nil {
		return err
	}
	return store.ReplaceRemote(ctx, group, nodes, 0)
}

func (s *SQLiteContractNodeStore) DeleteNode(id string) error {
	ctx := context.Background()
	store, err := s.open(ctx)
	if err != nil {
		return err
	}
	tx, err := store.DB().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin node delete transaction failed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM node_tags WHERE target_kind = 'node' AND target_id = ?`, id); err != nil {
		return fmt.Errorf("delete node tag members for %q failed: %w", id, err)
	}
	if err := plainstore.DeleteNodeContract(ctx, tx, id); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit node delete transaction failed: %w", err)
	}
	return nil
}

func (s *SQLiteContractNodeStore) GetContractNode(id string) (contractnode.Node, bool, error) {
	ctx := context.Background()
	nodes, err := s.nodeStore(ctx)
	if err != nil {
		return contractnode.Node{}, false, err
	}
	node, err := nodes.Get(ctx, id)
	if errors.Is(err, plainstore.ErrNotFound) {
		return contractnode.Node{}, false, nil
	}
	return node, err == nil, err
}

func (s *SQLiteContractNodeStore) ListContractNodes() ([]contractnode.Node, error) {
	ctx := context.Background()
	nodes, err := s.nodeStore(ctx)
	if err != nil {
		return nil, err
	}
	return nodes.List(ctx)
}

func (s *SQLiteContractNodeStore) GetContractNow(tcp bool) (contractnode.Node, bool, error) {
	ctx := context.Background()
	store, err := s.open(ctx)
	if err != nil {
		return contractnode.Node{}, false, err
	}
	key := selectedUDPNodeMetadataKey
	if tcp {
		key = selectedTCPNodeMetadataKey
	}
	id, err := loadMetadata(ctx, store.DB(), key)
	if err != nil || id == "" {
		return contractnode.Node{}, false, err
	}
	nodes := plainstore.NewNodeStore(store.DB())
	node, err := nodes.Get(ctx, id)
	if errors.Is(err, plainstore.ErrNotFound) {
		return contractnode.Node{}, false, nil
	}
	return node, err == nil, err
}

func (s *SQLiteContractNodeStore) UsePoint(id string) error {
	ctx := context.Background()
	store, err := s.open(ctx)
	if err != nil {
		return err
	}
	nodes := plainstore.NewNodeStore(store.DB())
	if _, err := nodes.Get(ctx, id); err != nil {
		return err
	}
	return updateMetadata(ctx, store.DB(), map[string]string{
		selectedTCPNodeMetadataKey: id,
		selectedUDPNodeMetadataKey: id,
	})
}

func (s *SQLiteContractNodeStore) AddContractTag(tag, kind, target string) error {
	ctx := context.Background()
	store, err := s.open(ctx)
	if err != nil {
		return err
	}
	if kind == "" {
		kind = "node"
	}
	if kind != "node" && kind != "tag" {
		return fmt.Errorf("unknown node tag target kind %q", kind)
	}
	if tag == target && kind == "tag" {
		return nil
	}
	if _, err := store.DB().ExecContext(ctx, `
		INSERT INTO node_tags(tag_name, target_kind, target_id, updated_at)
		VALUES (?, ?, ?, unixepoch())
		ON CONFLICT(tag_name, target_kind, target_id) DO UPDATE SET updated_at = excluded.updated_at
	`, tag, kind, target); err != nil {
		return fmt.Errorf("insert node tag failed: %w", err)
	}
	return nil
}

func (s *SQLiteContractNodeStore) DeleteTag(tag string) error {
	ctx := context.Background()
	store, err := s.open(ctx)
	if err != nil {
		return err
	}
	if _, err := store.DB().ExecContext(ctx, `DELETE FROM node_tags WHERE tag_name = ?`, tag); err != nil {
		return fmt.Errorf("delete node tag %q failed: %w", tag, err)
	}
	return nil
}

func (s *SQLiteContractNodeStore) GetContractTag(tag string) (string, []string, bool, error) {
	ctx := context.Background()
	nodes, err := s.nodeStore(ctx)
	if err != nil {
		return "", nil, false, err
	}
	out, ok, err := nodes.GetTag(ctx, tag)
	if err != nil {
		return "", nil, false, err
	}
	return out.Kind, out.TargetIDs, ok, nil
}

func (s *SQLiteContractNodeStore) UsingContractPoints() (*set.Set[string], error) {
	ctx := context.Background()
	nodes, err := s.nodeStore(ctx)
	if err != nil {
		return nil, err
	}
	ids, err := nodes.UsingIDs(ctx)
	if err != nil {
		return nil, err
	}
	out := set.NewSet[string]()
	for _, id := range ids {
		out.Push(id)
	}
	return out, nil
}

func (s *SQLiteContractNodeStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.store == nil {
		return nil
	}
	err := s.store.Close()
	s.store = nil
	s.nodes = nil
	return err
}

func loadMetadata(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, key string) (string, error) {
	var value string
	err := q.QueryRowContext(ctx, `SELECT value FROM metadata WHERE key = ?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("load metadata %q failed: %w", key, err)
	}
	return value, nil
}

func updateMetadata(ctx context.Context, execer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, values map[string]string) error {
	for key, value := range values {
		if _, err := execer.ExecContext(ctx, `
			INSERT INTO metadata(key, value)
			VALUES (?, ?)
			ON CONFLICT(key) DO UPDATE SET value = excluded.value
		`, key, value); err != nil {
			return fmt.Errorf("update metadata %q failed: %w", key, err)
		}
	}
	return nil
}
