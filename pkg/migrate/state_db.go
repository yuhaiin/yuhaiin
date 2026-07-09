package migrate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	legacymigrate "github.com/Asutorufa/yuhaiin/pkg/legacy/migrate"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

const plainModelMigrationDoneKey = "plain_model_migration_done"

type StateDB struct {
	path  string
	inner interface {
		SQLDB(context.Context) (*sql.DB, error)
		Migrate(context.Context) error
		Close() error
	}
}

func NewStateDB(path string) *StateDB {
	return &StateDB{
		path:  path,
		inner: legacymigrate.NewStateDB(path),
	}
}

func (s *StateDB) SQLDB(ctx context.Context) (*sql.DB, error) {
	return s.inner.SQLDB(ctx)
}

func (s *StateDB) Close() error {
	return s.inner.Close()
}

func (s *StateDB) Migrate(ctx context.Context) error {
	if s == nil || s.inner == nil {
		return errors.New("state db is nil")
	}
	if err := s.backupIfNeeded(ctx); err != nil {
		return err
	}
	if err := s.inner.Migrate(ctx); err != nil {
		return fmt.Errorf("run legacy-to-plain migration failed: %w", err)
	}
	db, err := s.inner.SQLDB(ctx)
	if err != nil {
		return err
	}
	if err := legacymigrate.MigrateLegacyBackup(ctx, db, 0); err != nil {
		return err
	}
	if err := migrateStatisticConnectionJSON(ctx, db); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO metadata(key, value)
		VALUES (?, '1')
		ON CONFLICT(key) DO UPDATE SET value = excluded.value
	`, plainModelMigrationDoneKey); err != nil {
		return fmt.Errorf("mark plain model migration done failed: %w", err)
	}
	return nil
}

func (s *StateDB) backupIfNeeded(ctx context.Context) error {
	if s.path == "" {
		return nil
	}
	if _, err := os.Stat(s.path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("stat state db before migration failed: %w", err)
	}

	store, err := storagesqlite.Open(ctx, s.path)
	if err != nil {
		return fmt.Errorf("open state db before migration backup failed: %w", err)
	}
	defer store.Close()

	done, err := migrationMarker(ctx, store.DB(), plainModelMigrationDoneKey)
	if err != nil {
		return err
	}
	if done == "1" {
		return nil
	}

	backupPath := filepath.Join(filepath.Dir(s.path), fmt.Sprintf("%s.plain-migration-%d.bak", filepath.Base(s.path), time.Now().Unix()))
	if _, err := store.DB().ExecContext(ctx, "VACUUM INTO '"+sqliteStringLiteral(backupPath)+"'"); err != nil {
		return fmt.Errorf("backup state db before plain migration failed: %w", err)
	}
	fmt.Printf("plain model migration backup: %s\n", backupPath)
	return nil
}

func migrationMarker(ctx context.Context, db *sql.DB, key string) (string, error) {
	var value string
	err := db.QueryRowContext(ctx, `SELECT value FROM metadata WHERE key = ?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("load migration marker %q failed: %w", key, err)
	}
	return value, nil
}

func sqliteStringLiteral(path string) string {
	return strings.ReplaceAll(path, "'", "''")
}
