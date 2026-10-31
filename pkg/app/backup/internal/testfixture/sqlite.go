package testfixture

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

type openStore func(context.Context, string) (*sqlite.Store, error)

var configurationTemplate = sync.OnceValues(func() ([]byte, error) { return databaseTemplate(sqlite.Open) })
var managementTemplate = sync.OnceValues(func() ([]byte, error) { return databaseTemplate(sqlite.OpenManagement) })
var seedMu sync.Mutex

// OpenState gives each fixture a private, fully migrated configuration database.
// Existing files still go through the real opener, including schema validation.
// Migration and historical-schema tests must use sqlite.Open directly.
func OpenState(ctx context.Context, path string) (*sqlite.Store, error) {
	return openFixture(ctx, path, configurationTemplate, sqlite.Open)
}

// OpenManagement is the corresponding fixture for the separate identity schema.
func OpenManagement(ctx context.Context, path string) (*sqlite.Store, error) {
	return openFixture(ctx, path, managementTemplate, sqlite.OpenManagement)
}

func openFixture(ctx context.Context, path string, template func() ([]byte, error), open openStore) (*sqlite.Store, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := seedDatabase(path, template); err != nil {
		return nil, err
	}
	return open(ctx, path)
}

func seedDatabase(path string, template func() ([]byte, error)) error {
	seedMu.Lock()
	defer seedMu.Unlock()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return err
	}
	data, err := template()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	return errors.Join(writeErr, file.Close())
}

func databaseTemplate(open openStore) ([]byte, error) {
	directory, err := os.MkdirTemp("", "yuhaiin-sqlite-fixture-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(directory)
	path := filepath.Join(directory, "template.db")
	// The template outlives the first caller's test context. Close the only
	// connection before reading so committed WAL data is in the standalone file.
	db, err := open(context.Background(), path)
	if err != nil {
		return nil, err
	}
	if err := db.Close(); err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}
