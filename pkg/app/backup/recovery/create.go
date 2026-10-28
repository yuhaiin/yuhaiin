package recovery

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
	"uuid"

	"github.com/Asutorufa/yuhaiin/internal/version"
	"github.com/Asutorufa/yuhaiin/pkg/app/backup/internal/backupfs"
	backupsnapshot "github.com/Asutorufa/yuhaiin/pkg/app/backup/internal/snapshot"
	contractrecovery "github.com/Asutorufa/yuhaiin/pkg/contract/backup/recovery"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
	backuparchive "github.com/Asutorufa/yuhaiin/pkg/store/backup/archive"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lockfile"
)

type CreateOptions struct {
	ConfirmedMaintenance bool
	IncludeHistory       bool
	Runtime              *contractrecovery.Runtime
	checkSpace           func(string, int64) error
}

// Create creates a complete, encrypted snapshot set through the
// existing backup/storage owners. The service and external identity/certificate
// writers must be stopped. The lifecycle lock excludes cooperating instances;
// the explicit maintenance acknowledgement also covers older/embedded writers.
func Create(ctx context.Context, directory, destination string, key backuparchive.Encryption, options CreateOptions) (contractrecovery.Manifest, error) {
	var empty contractrecovery.Manifest
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
	if err := GuardMaintenance(directory); err != nil {
		return empty, err
	}
	if err := sqlite.RequireClosed(filepath.Join(directory, "state.db"), filepath.Join(directory, "management.db")); err != nil {
		return empty, err
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	checkSpace := options.checkSpace
	if checkSpace == nil {
		checkSpace = backupfs.CheckStagingSpace
	}
	if err := checkSpace(directory, 0); err != nil {
		return empty, err
	}
	if err := checkSpace(filepath.Dir(destination), 0); err != nil {
		return empty, err
	}
	snapshot, err := os.MkdirTemp(directory, ".recovery-snapshot-*")
	if err != nil {
		return empty, err
	}
	defer os.RemoveAll(snapshot)
	manifest := contractrecovery.Manifest{
		ID: uuid.New().String(), CreatedAt: time.Now().UTC(), Consistency: "offline-maintenance", IncludesHistory: options.IncludeHistory,
		SourceDirectory: directory, Build: contractrecovery.Build{Version: version.Version, Commit: version.GitCommit, Platform: runtime.GOOS, Architecture: runtime.GOARCH, GoVersion: runtime.Version()},
	}
	var databaseBytes int64
	for _, database := range []struct{ name, kind, role string }{{"state.db", "configuration", "configuration_database"}, {"management.db", "management", "management_database"}} {
		source := filepath.Join(directory, database.name)
		if _, err := os.Lstat(source); errors.Is(err, os.ErrNotExist) && database.kind == "management" {
			continue
		} else if err != nil {
			return empty, err
		}
		schema, err := sqlite.SnapshotRecoveryDatabaseWithSpaceCheck(ctx, source, filepath.Join(snapshot, database.name), database.kind, backuparchive.MaxDataBytes-databaseBytes, func(bytes int64) error {
			return checkSpace(snapshot, bytes)
		})
		if err != nil {
			return empty, fmt.Errorf("snapshot %s: %w", database.name, err)
		}
		info, err := os.Stat(filepath.Join(snapshot, database.name))
		if err != nil {
			return empty, err
		}
		databaseBytes += info.Size()
		manifest.Files = append(manifest.Files, contractrecovery.File{Path: database.name, Role: database.role, SchemaVersion: schema})
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
		inputs, err = backupstore.LoadRecoveryRuntime(ctx, reader)
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
	collector.checkSpace = checkSpace
	err = collector.collect(reader)
	closeErr := reader.Close()
	if err != nil {
		return empty, err
	}
	if closeErr != nil {
		return empty, closeErr
	}
	if err := backupsnapshot.PruneRecovery(ctx, filepath.Join(snapshot, "state.db"), options.IncludeHistory); err != nil {
		return empty, err
	}
	manifest.Runtime = inputs
	manifest.CompleteInventory = true
	// Reserve ciphertext while the complete plaintext set is still allocated.
	// age adds one tag per 64 KiB chunk; two MiB covers the bounded manifest,
	// framing, recipient header and final chunk. Pruning may make this estimate
	// conservative. Check the output filesystem separately from staging.
	cipherBytes := collector.bytes + (collector.bytes/(64<<10)+1)*16 + (2 << 20)
	if err := checkSpace(filepath.Dir(destination), cipherBytes); err != nil {
		return empty, err
	}
	return backuparchive.WriteFile(ctx, destination, snapshot, manifest, key)
}
