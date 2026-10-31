//go:build sqlite_modernc || (!sqlite_mattn && ((android && !cgo && (386 || amd64 || arm || arm64)) || (!android && (((darwin || freebsd) && (amd64 || arm64)) || (linux && (386 || amd64 || arm || arm64 || loong64 || ppc64le || riscv64 || s390x)) || (openbsd && (amd64 || arm64)) || (windows && (386 || amd64 || arm64))))))

package sqlite

import (
	"database/sql"
	"errors"
	"fmt"

	moderncsqlite "modernc.org/sqlite"
	sqlitelib "modernc.org/sqlite/lib"
)

func restrictBackupSnapshot(conn *sql.Conn) error {
	for id, limit := range map[int]int{sqlitelib.SQLITE_LIMIT_LENGTH: 64 << 20, sqlitelib.SQLITE_LIMIT_SQL_LENGTH: 1 << 20, sqlitelib.SQLITE_LIMIT_EXPR_DEPTH: 64} {
		if _, err := moderncsqlite.Limit(conn, id, limit); err != nil {
			return err
		}
	}
	return nil
}

const (
	backendName = "modernc.org/sqlite"
	driverName  = "sqlite"
)

func sqliteErrorDetails(err error) string {
	sqliteErr, ok := errors.AsType[*moderncsqlite.Error](err)
	if !ok {
		return ""
	}

	description := moderncsqlite.ErrorCodeString[sqliteErr.Code()]
	if description == "" {
		description = "unknown"
	}

	return fmt.Sprintf(" (code=%d %s)", sqliteErr.Code(), description)
}
