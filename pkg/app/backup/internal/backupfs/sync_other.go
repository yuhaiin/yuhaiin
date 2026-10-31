//go:build !windows

package backupfs

import "os"

// Sync commits a recovery file or directory before its journal advances.
func Sync(file *os.File) error { return file.Sync() }
