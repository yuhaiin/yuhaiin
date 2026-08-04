//go:build sqlite_ncruces || (!sqlite_modernc && !sqlite_mattn && ((!android && !(((darwin || freebsd) && (amd64 || arm64)) || (linux && (386 || amd64 || arm || arm64 || loong64 || ppc64le || riscv64 || s390x)) || (openbsd && (amd64 || arm64)) || (windows && (386 || amd64 || arm64)))) || (android && cgo && !(fts5 || sqlite_fts5)))) || (sqlite_mattn && !(cgo && (fts5 || sqlite_fts5)))

package sqlite

import (
	"errors"
	"fmt"

	sqlite3 "github.com/ncruces/go-sqlite3"
	_ "github.com/ncruces/go-sqlite3/driver"
	"github.com/ncruces/go-sqlite3/ext/fts5"
)

const (
	backendName = "github.com/ncruces/go-sqlite3"
	driverName  = "sqlite3"
)

func init() {
	sqlite3.AutoExtension(fts5.Register)
}

func sqliteErrorDetails(err error) string {
	if sqliteErr, ok := errors.AsType[*sqlite3.Error](err); ok {
		return fmt.Sprintf(" (code=%d extended_code=%d)", sqliteErr.Code(), sqliteErr.ExtendedCode())
	}
	if extendedCode, ok := errors.AsType[sqlite3.ExtendedErrorCode](err); ok {
		return fmt.Sprintf(" (code=%d extended_code=%d)", extendedCode.Code(), extendedCode)
	}
	if code, ok := errors.AsType[sqlite3.ErrorCode](err); ok {
		return fmt.Sprintf(" (code=%d)", code)
	}
	return ""
}
