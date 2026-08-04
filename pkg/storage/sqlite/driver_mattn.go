//go:build (sqlite_mattn || (!sqlite_modernc && !sqlite_ncruces && android && cgo)) && (fts5 || sqlite_fts5)

package sqlite

import (
	"errors"
	"fmt"

	mattnsqlite "github.com/mattn/go-sqlite3"
)

const (
	backendName = "github.com/mattn/go-sqlite3"
	driverName  = "sqlite3"
)

func sqliteErrorDetails(err error) string {
	var sqliteErr mattnsqlite.Error
	if !errors.As(err, &sqliteErr) {
		return ""
	}

	return fmt.Sprintf(
		" (code=%d extended_code=%d system_errno=%d)",
		sqliteErr.Code,
		sqliteErr.ExtendedCode,
		sqliteErr.SystemErrno,
	)
}
