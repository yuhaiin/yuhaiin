//go:build sqlite_modernc || (!sqlite_mattn && ((android && !cgo && (386 || amd64 || arm || arm64)) || (!android && (((darwin || freebsd) && (amd64 || arm64)) || (linux && (386 || amd64 || arm || arm64 || loong64 || ppc64le || riscv64 || s390x)) || (openbsd && (amd64 || arm64)) || (windows && (386 || amd64 || arm64))))))

package sqlite

import (
	"errors"
	"fmt"

	moderncsqlite "modernc.org/sqlite"
)

const (
	backendName = "modernc.org/sqlite"
	driverName  = "sqlite"
)

func sqliteErrorDetails(err error) string {
	var sqliteErr *moderncsqlite.Error
	if !errors.As(err, &sqliteErr) {
		return ""
	}

	description := moderncsqlite.ErrorCodeString[sqliteErr.Code()]
	if description == "" {
		description = "unknown"
	}

	return fmt.Sprintf(" (code=%d %s)", sqliteErr.Code(), description)
}
