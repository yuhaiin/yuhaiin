//go:build (!cgo || sqlite_purego) && !sqlite_cgo && !android && !ios && (((linux || darwin || windows) && (amd64 || arm64)) || (freebsd && amd64))

package sqlite

import (
	"fmt"
	"runtime"

	"github.com/Asutorufa/yuhaiin/internal/sqliteabi"
	nativesqlite "github.com/yuhaiin/purego-sqlite"
	sqliteembed "github.com/yuhaiin/purego-sqlite-embed"
)

func sqliteOptions() ([]nativesqlite.Option, error) {
	if runtime.GOOS == "linux" && sqliteabi.LinuxABI() != "glibc" {
		return nil, fmt.Errorf("embedded SQLite needs glibc >= %s; build with CGO_ENABLED=1 -tags=sqlite_cgo for the static engine", sqliteabi.MinimumGlibc)
	}
	path, err := sqliteembed.Path()
	if err != nil {
		return nil, err
	}
	return []nativesqlite.Option{nativesqlite.WithLibrary(path)}, nil
}
