package yuhaiin

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Asutorufa/yuhaiin/pkg/migrate"
	"github.com/Asutorufa/yuhaiin/pkg/paths"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lockfile"
)

func withConfigDB(fn func(context.Context, *storagesqlite.Store) error) error {
	if savepath == "" {
		return errors.New("configuration path is not initialized")
	}
	ctx := context.Background()
	state := migrate.NewStateDB(paths.PathGenerator.State(savepath))
	defer func() { _ = state.Close() }()
	if err := state.Migrate(ctx); err != nil {
		return err
	}
	store, err := storagesqlite.Open(ctx, paths.PathGenerator.State(savepath))
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()
	return fn(ctx, store)
}

// ExportConfig includes core configuration and Android preferences, but no
// live sessions, traffic history, caches or installer/document identifiers.
func ExportConfig() ([]byte, error) {
	var data []byte
	err := withConfigDB(func(ctx context.Context, store *storagesqlite.Store) (err error) {
		data, err = storagesqlite.ExportConfig(ctx, store.DB())
		return err
	})
	return data, err
}

func ValidateConfig(data []byte) error {
	return withConfigDB(func(ctx context.Context, store *storagesqlite.Store) error {
		return storagesqlite.ValidateConfig(ctx, store.DB(), data)
	})
}

// ImportConfig requires the Android VPN service to be disconnected. It restores
// atomically without swapping state.db or invalidating other processes' handles.
func ImportConfig(data []byte) error {
	lock, err := lockConfiguration()
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	return withConfigDB(func(ctx context.Context, store *storagesqlite.Store) error {
		return storagesqlite.RestoreConfig(ctx, store.DB(), data)
	})
}

var configLockPath string

// SetConfigLockPath selects private app storage for the lifecycle lock. Android
// emulated external storage does not implement flock even when state.db works.
func SetConfigLockPath(path string) { configLockPath = path }

// Keep the file in place: unlinking a locked inode would allow another process
// to lock a different inode while the first holder is still using the database.
func lockConfiguration() (*os.File, error) {
	if savepath == "" {
		return nil, errors.New("configuration path is not initialized")
	}
	lockPath := configLockPath
	if lockPath == "" {
		lockPath = filepath.Join(savepath, ".configuration.lock")
	}
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := lockfile.LockFile(file); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("configuration is in use; disconnect the VPN before restoring: %w", err)
	}
	return file, nil
}
