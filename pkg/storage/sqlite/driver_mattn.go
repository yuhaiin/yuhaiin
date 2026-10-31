//go:build sqlite_mattn || (!sqlite_modernc && ((!android && !(((darwin || freebsd) && (amd64 || arm64)) || (linux && (386 || amd64 || arm || arm64 || loong64 || ppc64le || riscv64 || s390x)) || (openbsd && (amd64 || arm64)) || (windows && (386 || amd64 || arm64)))) || (android && cgo)))

package sqlite

import (
	"database/sql"
	"errors"
	"fmt"

	mattnsqlite "github.com/mattn/go-sqlite3"
)

func restrictBackupSnapshot(conn *sql.Conn) error {
	return conn.Raw(func(value any) error {
		sqliteConn, ok := value.(*mattnsqlite.SQLiteConn)
		if !ok {
			return errors.New("unexpected SQLite snapshot connection")
		}
		sqliteConn.SetLimit(mattnsqlite.SQLITE_LIMIT_LENGTH, 64<<20)
		sqliteConn.SetLimit(mattnsqlite.SQLITE_LIMIT_SQL_LENGTH, 1<<20)
		sqliteConn.SetLimit(mattnsqlite.SQLITE_LIMIT_EXPR_DEPTH, 64)
		return nil
	})
}

const (
	backendName = "github.com/mattn/go-sqlite3"
	driverName  = "sqlite3"
)

func sqliteErrorDetails(err error) string {
	sqliteErr, ok := errors.AsType[mattnsqlite.Error](err)
	if !ok {
		return ""
	}

	return fmt.Sprintf(
		" (code=%d extended_code=%d system_errno=%d)",
		sqliteErr.Code,
		sqliteErr.ExtendedCode,
		sqliteErr.SystemErrno,
	)
}
