package sqlite

import (
	"sync/atomic"
)

var nfsMode atomic.Bool

// SetNFSMode selects the SQLite configuration used by subsequently opened
// databases. It must be called before opening the first database in a process.
func SetNFSMode(enabled bool) {
	nfsMode.Store(enabled)
}

func NFSMode() bool {
	return nfsMode.Load()
}

const (
	sqliteExpectedLockingMode = "normal"
	sqliteExpectedSynchronous = 1
	sqliteExpectedBusyTimeout = 5000
)

func sqlitePragmas() []string {
	if NFSMode() {
		return []string{
			"PRAGMA journal_mode = DELETE",
			"PRAGMA locking_mode = EXCLUSIVE",
			"PRAGMA synchronous = FULL",
			"PRAGMA foreign_keys = ON",
			"PRAGMA busy_timeout = 30000",
		}
	}

	return []string{
		"PRAGMA journal_mode = WAL",
		"PRAGMA synchronous = NORMAL",
		"PRAGMA foreign_keys = ON",
		"PRAGMA busy_timeout = 5000",
	}
}
