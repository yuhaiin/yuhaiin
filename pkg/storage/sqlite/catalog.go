package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// MigrationDescriptor is public schema metadata, never SQL or deployment data.
// Transform identifies migrations which also execute versioned Go transforms;
// it does not imply that a transformation can be reversed.
type MigrationDescriptor struct {
	Version   int    `json:"version"`
	Name      string `json:"name"`
	SHA256    string `json:"sha256"`
	Transform bool   `json:"transform,omitzero"`
}

func MigrationCatalog(kind string) ([]MigrationDescriptor, error) {
	known, err := knownMigrations(kind)
	if err != nil {
		return nil, err
	}
	result := make([]MigrationDescriptor, 0, len(known))
	for _, migration := range known {
		data, err := json.Marshal(migration.Statements)
		if err != nil {
			return nil, err
		}
		hash := sha256.Sum256(data)
		result = append(result, MigrationDescriptor{Version: migration.Version, Name: migration.Name, SHA256: hex.EncodeToString(hash[:]), Transform: migration.Transform != nil})
	}
	return result, nil
}

// InspectStoreCatalog reads actual live WAL state without bootstrap, migration,
// checkpointing or immutable=1. A read transaction keeps metadata and migration
// names consistent. This is a bounded management operation, never a dial-path read.
func InspectStoreCatalog(ctx context.Context, path, kind string) ([]MigrationDescriptor, error) {
	db, err := OpenLiveReader(ctx, path)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := checkStoreCompatibility(ctx, tx, kind); err != nil {
		return nil, err
	}
	known, err := knownMigrations(kind)
	if err != nil {
		return nil, err
	}
	count, _, err := migrationPrefix(ctx, tx, known)
	if err != nil {
		return nil, err
	}
	catalog, err := MigrationCatalog(kind)
	if err != nil {
		return nil, err
	}
	return catalog[:count], nil
}

// OpenLiveReader reads committed WAL state without bootstrap or migrations.
// The caller must close it. Use OpenSnapshotReader only for isolated standalone
// snapshots; immutable mode would ignore a running deployment's WAL.
func OpenLiveReader(ctx context.Context, path string) (*sql.DB, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("schema inspection requires an owned regular database")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	uri := &url.URL{Scheme: "file", Path: filepath.ToSlash(absolute), RawQuery: "mode=ro"}
	if filepath.VolumeName(absolute) != "" && !strings.HasPrefix(uri.Path, "/") {
		uri.Path = "/" + uri.Path
	}
	db, err := sql.Open(driverName, uri.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, "PRAGMA query_only=ON; PRAGMA trusted_schema=OFF; PRAGMA busy_timeout=1000"); err != nil {
		_ = db.Close()
		return nil, err
	}

	return db, nil
}
