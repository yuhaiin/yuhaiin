package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	sqlite3 "github.com/ncruces/go-sqlite3"
	_ "github.com/ncruces/go-sqlite3/driver"
	"github.com/ncruces/go-sqlite3/ext/fts5"
)

const driverName = "sqlite3"

func init() {
	sqlite3.AutoExtension(fts5.Register)
}

type Store struct {
	shared *sharedStore
	closed bool
}

type sharedStore struct {
	path string
	db   *sql.DB
	refs int
}

var sharedSQLite = struct {
	sync.Mutex
	stores map[string]*sharedStore
}{
	stores: map[string]*sharedStore{},
}

func Open(ctx context.Context, path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("sqlite path is empty")
	}

	path, err := canonicalPath(path)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create sqlite directory failed: %w", err)
	}

	sharedSQLite.Lock()
	defer sharedSQLite.Unlock()

	if shared := sharedSQLite.stores[path]; shared != nil {
		shared.refs++
		return &Store{shared: shared}, nil
	}

	db, err := sql.Open(driverName, path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite failed: %w", err)
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if err := configure(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}

	if err := Bootstrap(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}

	shared := &sharedStore{
		path: path,
		db:   db,
		refs: 1,
	}
	sharedSQLite.stores[path] = shared

	return &Store{shared: shared}, nil
}

func canonicalPath(path string) (string, error) {
	path = filepath.Clean(path)
	if filepath.IsAbs(path) {
		return path, nil
	}

	path, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve sqlite path failed: %w", err)
	}
	return path, nil
}

func (s *Store) DB() *sql.DB {
	if s == nil || s.shared == nil {
		return nil
	}
	return s.shared.db
}

func (s *Store) Path() string {
	if s == nil || s.shared == nil {
		return ""
	}
	return s.shared.path
}

func (s *Store) Close() error {
	if s == nil || s.shared == nil || s.closed {
		return nil
	}

	sharedSQLite.Lock()
	defer sharedSQLite.Unlock()

	s.closed = true
	s.shared.refs--
	if s.shared.refs > 0 {
		return nil
	}

	delete(sharedSQLite.stores, s.shared.path)
	return s.shared.db.Close()
}

func Bootstrap(ctx context.Context, db *sql.DB) error {
	if err := bootstrapBase(ctx, db); err != nil {
		return err
	}

	applied, err := loadAppliedVersions(ctx, db)
	if err != nil {
		return err
	}

	for _, migration := range migrations {
		if _, ok := applied[migration.Version]; ok {
			continue
		}

		if err := applyMigration(ctx, db, migration); err != nil {
			return err
		}
	}

	return nil
}

func configure(ctx context.Context, db *sql.DB) error {
	for _, stmt := range []string{
		"PRAGMA journal_mode = WAL",
		"PRAGMA synchronous = NORMAL",
		"PRAGMA foreign_keys = ON",
		"PRAGMA busy_timeout = 5000",
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("configure sqlite with %q failed: %w", stmt, err)
		}
	}

	return nil
}

func bootstrapBase(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin sqlite bootstrap transaction failed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS metadata (
			key   TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS migrate (
			version     INTEGER PRIMARY KEY,
			name        TEXT NOT NULL,
			applied_at  INTEGER NOT NULL
		)`,
	} {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("execute bootstrap statement failed: %w", err)
		}
	}

	if err := ensureMetadataDefaults(ctx, tx); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit sqlite bootstrap transaction failed: %w", err)
	}

	return nil
}

func ensureMetadataDefaults(ctx context.Context, execer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}) error {
	now := strconv.FormatInt(time.Now().Unix(), 10)

	if _, err := execer.ExecContext(ctx, `
		INSERT INTO metadata(key, value)
		VALUES ('created_at', ?)
		ON CONFLICT(key) DO NOTHING
	`, now); err != nil {
		return fmt.Errorf("ensure metadata created_at failed: %w", err)
	}

	return nil
}

func loadAppliedVersions(ctx context.Context, db *sql.DB) (map[int]struct{}, error) {
	rows, err := db.QueryContext(ctx, `SELECT version FROM migrate`)
	if err != nil {
		return nil, fmt.Errorf("query applied sqlite migrations failed: %w", err)
	}
	defer rows.Close()

	applied := make(map[int]struct{})
	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			return nil, fmt.Errorf("scan applied sqlite migration failed: %w", err)
		}
		applied[version] = struct{}{}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate applied sqlite migrations failed: %w", err)
	}

	return applied, nil
}

func applyMigration(ctx context.Context, db *sql.DB, migration Migration) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin sqlite migration %d failed: %w", migration.Version, err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, stmt := range migration.Statements {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("execute sqlite migration %d statement failed: %w", migration.Version, err)
		}
	}

	now := time.Now().Unix()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO migrate(version, name, applied_at)
		VALUES (?, ?, ?)
	`, migration.Version, migration.Name, now); err != nil {
		return fmt.Errorf("record sqlite migration %d failed: %w", migration.Version, err)
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO metadata(key, value)
		VALUES ('schema_version', ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value
	`, strconv.Itoa(migration.Version)); err != nil {
		return fmt.Errorf("update sqlite schema_version metadata failed: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit sqlite migration %d failed: %w", migration.Version, err)
	}

	return nil
}
