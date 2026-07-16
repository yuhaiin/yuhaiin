//go:build yuhaiin_nfs

package sqlite

// NFS builds avoid WAL's mmap-backed shared-memory index and use a single
// exclusive connection. This reduces the amount of locking and shared-memory
// coordination delegated to the network filesystem.
const (
	sqliteExpectedJournalMode = "delete"
	sqliteExpectedLockingMode = "exclusive"
	sqliteExpectedSynchronous = 2
	sqliteExpectedBusyTimeout = 30000
)

func sqlitePragmas() []string {
	return []string{
		"PRAGMA journal_mode = DELETE",
		"PRAGMA locking_mode = EXCLUSIVE",
		"PRAGMA synchronous = FULL",
		"PRAGMA foreign_keys = ON",
		"PRAGMA busy_timeout = 30000",
	}
}
