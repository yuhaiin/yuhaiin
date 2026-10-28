package recovery

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"
	"uuid"

	backupfs "github.com/Asutorufa/yuhaiin/pkg/app/backup/internal/backupfs"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
	backuparchive "github.com/Asutorufa/yuhaiin/pkg/store/backup/archive"
	"github.com/Asutorufa/yuhaiin/pkg/store/backup/privatefs"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lockfile"
)

// Legacy S3 objects are configuration imports, never deployment identity
// replacements. Stop owners, apply the existing configuration importer to a
// private copy of the local store, then use the same activation/startup journal.
func RestoreConfiguration(ctx context.Context, directory string, data []byte) error {
	if len(data) == 0 || len(data) > 64<<20 {
		return errors.New("legacy configuration object exceeds the 64 MiB compatibility limit")
	}
	directory, err := backupfs.CanonicalDirectory(directory)
	if err != nil {
		return err
	}
	lifecycle, err := lockfile.Acquire(filepath.Join(directory, ".configuration.lock"))
	if err != nil {
		return err
	}
	defer lifecycle.Close()
	if err := requireRecoveryLifecycle(directory, lifecycle); err != nil {
		return err
	}
	if err := GuardMaintenance(directory); err != nil {
		return err
	}
	stage, err := privatefs.MkdirTemp(directory, ".recovery-stage-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	source := filepath.Join(stage, "legacy-input.db")
	if err := os.WriteFile(source, data, 0o600); err != nil {
		return err
	}
	if _, err := sqlite.InspectBackupSnapshot(ctx, source, "configuration"); err != nil {
		return err
	}
	input, err := sqlite.Open(ctx, source)
	if err != nil {
		return err
	}
	configuration, exportErr := sqlite.ExportConfig(ctx, input.DB())
	if err := errors.Join(exportErr, input.Close()); err != nil {
		return err
	}
	target := filepath.Join(stage, "state.db")
	if _, err := sqlite.SnapshotRecoveryDatabase(ctx, filepath.Join(directory, "state.db"), target, "configuration", backuparchive.MaxDataBytes); err != nil {
		return err
	}
	staged, err := sqlite.Open(ctx, target)
	if err != nil {
		return err
	}
	inputs, readErr := backupstore.LoadRecoveryRuntime(ctx, staged.DB())
	if readErr != nil || inputs == nil {
		_ = staged.Close()
		return errors.New("legacy offline restore requires recorded startup inputs from the current server")
	}
	instanceID, err := sqlite.RecoveryInstanceID(ctx, target, false)
	if err != nil {
		_ = staged.Close()
		return err
	}
	importErr := sqlite.RestoreConfig(ctx, staged.DB(), configuration)
	if err := errors.Join(importErr, staged.Close()); err != nil {
		return err
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer root.Close()
	tx := &recoveryTransaction{Version: 1, ID: uuid.New().String(), BackupID: uuid.New().String(), InstanceID: instanceID, CreatedAt: time.Now().UTC(), Phase: "activating", Stage: filepath.Base(stage), Runtime: *inputs}
	for _, path := range []string{"state.db", "state.db-wal", "state.db-shm", "state.db-journal"} {
		exists, err := backupfs.Destination(root, path, false)
		if err != nil {
			return err
		}
		tx.Moves = append(tx.Moves, recoveryMove{Path: path, HadOriginal: exists, Install: path == "state.db"})
	}
	return activateRecoverySet(ctx, directory, tx, nil)
}
