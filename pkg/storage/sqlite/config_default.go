//go:build !yuhaiin_nfs

package sqlite

const (
	sqliteExpectedJournalMode = "wal"
	sqliteExpectedLockingMode = "normal"
	sqliteExpectedSynchronous = 1
	sqliteExpectedBusyTimeout = 5000
)

func sqlitePragmas() []string {
	return []string{
		"PRAGMA journal_mode = WAL",
		"PRAGMA synchronous = NORMAL",
		"PRAGMA foreign_keys = ON",
		"PRAGMA busy_timeout = 5000",
	}
}
