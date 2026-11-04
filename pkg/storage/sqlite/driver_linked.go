//go:build cgo && !sqlite_purego

package sqlite

import nativesqlite "github.com/yuhaiin/purego-sqlite"

// CGO builds use the driver's default linked SQLite engine. This also provides
// the default backend on targets without PureGo or an embedded library.
func sqliteOptions() ([]nativesqlite.Option, error) { return nil, nil }
