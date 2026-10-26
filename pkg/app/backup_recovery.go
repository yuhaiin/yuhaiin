package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"
	"uuid"

	"github.com/Asutorufa/yuhaiin/internal/version"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	"github.com/Asutorufa/yuhaiin/pkg/store"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lockfile"
)

type RecoveryCreateOptions struct {
	ConfirmedMaintenance bool
	IncludeHistory       bool
	Runtime              *contract.RecoveryRuntime
}

// CreateOfflineRecovery creates a complete, encrypted snapshot set through the
// existing backup/storage owners. The service and external identity/certificate
// writers must be stopped. The lifecycle lock excludes cooperating instances;
// the explicit maintenance acknowledgement also covers older/embedded writers.
func CreateOfflineRecovery(ctx context.Context, directory, destination string, key store.RecoveryEncryption, options RecoveryCreateOptions) (contract.RecoveryManifest, error) {
	var empty contract.RecoveryManifest
	if err := key.Validate(); err != nil {
		return empty, err
	}
	if _, err := os.Lstat(destination); err == nil {
		return empty, errors.New("backup destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return empty, err
	}
	if !options.ConfirmedMaintenance {
		return empty, errors.New("full backup requires a confirmed maintenance window with all writers stopped")
	}
	directory, err := filepath.Abs(directory)
	if err != nil {
		return empty, err
	}
	directory, err = filepath.EvalSymlinks(directory)
	if err != nil {
		return empty, err
	}
	if info, err := os.Stat(directory); err != nil || !info.IsDir() {
		return empty, errors.New("backup source directory does not exist")
	}
	lifecycle, err := lockfile.Acquire(filepath.Join(directory, ".configuration.lock"))
	if err != nil {
		return empty, err
	}
	defer lifecycle.Close()
	if err := GuardRecoveryMaintenance(directory); err != nil {
		return empty, err
	}
	if err := sqlite.RequireClosed(filepath.Join(directory, "state.db"), filepath.Join(directory, "management.db")); err != nil {
		return empty, err
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	snapshot, err := os.MkdirTemp(directory, ".recovery-snapshot-*")
	if err != nil {
		return empty, err
	}
	defer os.RemoveAll(snapshot)
	manifest := contract.RecoveryManifest{
		ID: uuid.New().String(), CreatedAt: time.Now().UTC(), Consistency: "offline-maintenance", IncludesHistory: options.IncludeHistory,
		SourceDirectory: directory, Build: contract.RecoveryBuild{Version: version.Version, Commit: version.GitCommit, Platform: runtime.GOOS, Architecture: runtime.GOARCH, GoVersion: runtime.Version()},
	}
	var databaseBytes int64
	for _, database := range []struct{ name, kind, role string }{{"state.db", "configuration", "configuration_database"}, {"management.db", "management", "management_database"}} {
		source := filepath.Join(directory, database.name)
		if _, err := os.Lstat(source); errors.Is(err, os.ErrNotExist) && database.kind == "management" {
			continue
		} else if err != nil {
			return empty, err
		}
		schema, err := sqlite.SnapshotRecoveryDatabase(ctx, source, filepath.Join(snapshot, database.name), database.kind, store.MaxRecoveryDataBytes-databaseBytes)
		if err != nil {
			return empty, fmt.Errorf("snapshot %s: %w", database.name, err)
		}
		info, err := os.Stat(filepath.Join(snapshot, database.name))
		if err != nil {
			return empty, err
		}
		databaseBytes += info.Size()
		manifest.Files = append(manifest.Files, contract.RecoveryFile{Path: database.name, Role: database.role, SchemaVersion: schema})
	}
	// Validate every database before writing even the stable instance metadata.
	instanceID, err := sqlite.RecoveryInstanceID(ctx, filepath.Join(directory, "state.db"), false)
	if errors.Is(err, sql.ErrNoRows) {
		instanceID, err = sqlite.RecoveryInstanceID(ctx, filepath.Join(directory, "state.db"), true)
	}
	if err != nil {
		return empty, err
	}
	if err := sqlite.BindRecoveryInstance(ctx, filepath.Join(snapshot, "state.db"), instanceID); err != nil {
		return empty, err
	}
	manifest.InstanceID = instanceID
	reader, err := sqlite.OpenSnapshotReader(ctx, filepath.Join(snapshot, "state.db"))
	if err != nil {
		return empty, err
	}
	inputs := options.Runtime
	if inputs == nil {
		inputs, err = store.LoadRecoveryRuntime(ctx, reader)
	}
	if err != nil {
		_ = reader.Close()
		return empty, err
	}
	if inputs == nil {
		_ = reader.Close()
		return empty, errors.New("startup inputs are unavailable; supply explicit management TLS and working-directory inputs or run the updated server once")
	}
	collector := newRecoveryInventory(ctx, directory, snapshot, inputs, &manifest)
	err = collector.collect(reader)
	closeErr := reader.Close()
	if err != nil {
		return empty, err
	}
	if closeErr != nil {
		return empty, closeErr
	}
	if !options.IncludeHistory {
		if err := pruneRecoveryHistory(ctx, filepath.Join(snapshot, "state.db")); err != nil {
			return empty, err
		}
	}
	manifest.Runtime = inputs
	manifest.CompleteInventory = true
	return store.WriteRecoveryArchiveFile(ctx, destination, snapshot, manifest, key)
}

func pruneRecoveryHistory(ctx context.Context, path string) error {
	// Only the staged snapshot is changed. Account/credential state, traffic
	// quota totals, active measurement reservations and protocol identity remain.
	fileURL := &url.URL{Scheme: "file", Path: filepath.ToSlash(path), RawQuery: "mode=rw"}
	if filepath.VolumeName(path) != "" && !strings.HasPrefix(fileURL.Path, "/") {
		fileURL.Path = "/" + fileURL.Path
	}
	uri := fileURL.String()
	db, err := sql.Open(sqlite.DriverName(), uri)
	if err != nil {
		return err
	}
	defer db.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, table := range append(append([]string(nil), backupRuntimeTables...), "user_usage_audit") {
		if slices.Contains([]string{"statistics_kv", "fakeip_entries", "fakeip_cursors"}, table) {
			continue
		}
		var present int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name=?", table).Scan(&present); err != nil {
			return err
		}
		if present == 0 {
			continue
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+table); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, "VACUUM")
	return err
}
