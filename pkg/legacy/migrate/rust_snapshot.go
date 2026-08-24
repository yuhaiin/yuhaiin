package migrate

import (
	"context"

	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

// ExportRustSnapshot keeps the legacy migration entry point while delegating
// to the typed SQLite exporter.  Keeping one implementation makes the CLI and
// future in-process migration use the same FTS and consistency rules.
func ExportRustSnapshot(ctx context.Context, sourcePath, destinationPath string) (storagesqlite.RustSnapshotReport, error) {
	return storagesqlite.ExportRustSnapshot(ctx, sourcePath, destinationPath)
}
