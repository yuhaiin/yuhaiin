package backupfs

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func SyncDirectory(directory string) error {
	if runtime.GOOS == "windows" {
		return errors.ErrUnsupported
	}
	file, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

// Reject symlink components even when they stay inside the root: a transaction
// must not overwrite a second configuration through a directory alias.
func Destination(root *os.Root, name string, createParents bool) (bool, error) {
	parts := strings.Split(filepath.ToSlash(name), "/")
	parent := ""
	for _, part := range parts[:len(parts)-1] {
		parent = filepath.Join(parent, part)
		info, err := root.Lstat(parent)
		if errors.Is(err, os.ErrNotExist) && createParents {
			if err := root.Mkdir(parent, 0o700); err != nil {
				return false, err
			}
			directory, err := root.Open(filepath.Dir(parent))
			if err != nil {
				return false, err
			}
			err = errors.Join(directory.Sync(), directory.Close())
			if err != nil {
				return false, err
			}
			continue
		}
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return false, errors.New("recovery destination parent must be a real directory")
		}
	}
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, errors.New("recovery destination must be a regular file")
	}
	return true, nil
}
