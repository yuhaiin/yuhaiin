//go:build cgo && (sqlite_cgo || android || ios || !(((linux || darwin || windows) && (amd64 || arm64)) || (freebsd && amd64)))

package sqlite

import nativesqlite "github.com/yuhaiin/purego-sqlite"

// Unsupported embed/PureGo targets use the driver's default linked SQLite
// engine. These targets require CGO and a compiler matching the target ABI.
func sqliteOptions() ([]nativesqlite.Option, error) { return nil, nil }
