//go:build sqlite_mattn || (!sqlite_modernc && ((!android && !(((darwin || freebsd) && (amd64 || arm64)) || (linux && (386 || amd64 || arm || arm64 || loong64 || ppc64le || riscv64 || s390x)) || (openbsd && (amd64 || arm64)) || (windows && (386 || amd64 || arm64)))) || (android && cgo)))

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
