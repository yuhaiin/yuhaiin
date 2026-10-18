package migrate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

// StateDB owns the application SQLite handle. Schema migrations are managed by
// sqlite.Open/Bootstrap and are independent of retired JSON/protobuf imports.
type StateDB struct {
	path  string
	mu    sync.Mutex
	store *storagesqlite.Store
}

func NewStateDB(path string) *StateDB {
	return &StateDB{path: path}
}

func (s *StateDB) Migrate(ctx context.Context) error {
	if s == nil {
		return errors.New("state db is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.store != nil {
		return nil
	}

	store, err := storagesqlite.Open(ctx, s.path)
	if err != nil {
		return fmt.Errorf("initialize state sqlite database: %w", err)
	}
	if compacted, err := storagesqlite.CompactIfNeeded(ctx, store.DB()); err != nil {
		log.Warn("vacuum state on startup failed", "err", err)
	} else if compacted {
		log.Info("vacuum state database on startup")
	}

	s.store = store
	return nil
}

func (s *StateDB) SQLDB(_ context.Context) (*sql.DB, error) {
	if s == nil {
		return nil, errors.New("state db is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.store == nil {
		return nil, errors.New("state database has not been initialized; call Migrate before SQLDB")
	}
	return s.store.DB(), nil
}

func (s *StateDB) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.store == nil {
		return nil
	}
	err := s.store.Close()
	s.store = nil
	return err
}
