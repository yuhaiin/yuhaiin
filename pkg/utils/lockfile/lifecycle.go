package lockfile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Acquire holds a private lifecycle lock until the returned file is closed.
// Keep the inode in place: unlinking it would allow another owner to lock a new
// inode while a process still owns the old one. No payload/credentials are saved.
func Acquire(name string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(filepath.Dir(name))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	if info, err := root.Lstat(filepath.Base(name)); err == nil && !info.Mode().IsRegular() {
		return nil, errors.New("lifecycle lock must be a regular file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	file, err := root.OpenFile(filepath.Base(name), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := LockFile(file); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("data directory is in use or lifecycle locking is unavailable: %w", err)
	}
	return file, nil
}
