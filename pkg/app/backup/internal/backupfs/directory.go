package backupfs

import (
	"errors"
	"os"
	"path/filepath"
)

func CanonicalDirectory(directory string) (string, error) {
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return "", err
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(canonical)
	if err != nil || !info.IsDir() {
		return "", errors.New("recovery target must be an existing deployment directory")
	}
	return canonical, nil
}
