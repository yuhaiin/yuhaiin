//go:build !cgo && (sqlite_cgo || android || ios || !(((linux || darwin || windows) && (amd64 || arm64)) || (freebsd && amd64)))

package sqlite

import (
	"fmt"
	"runtime"

	nativesqlite "github.com/yuhaiin/purego-sqlite"
)

func sqliteOptions() ([]nativesqlite.Option, error) {
	return nil, fmt.Errorf("SQLite for %s/%s requires CGO_ENABLED=1 and a matching C toolchain for the linked native engine", runtime.GOOS, runtime.GOARCH)
}
