package recovery

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/app/backup/internal/backupfs"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
)

// GuardServiceMaintenance is called under the shared maintenance lease before
// replacing an executable. Admission may be committed in a live WAL before the
// restore writes a file transaction, so an immutable main-file read is unsafe.
func GuardServiceMaintenance(ctx context.Context, directory string) error {
	if err := GuardMaintenance(directory); err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(directory, "state.db")); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	return withRecoveryJobStore(ctx, directory, func(owner *backupstore.Store) error {
		pending, err := owner.RecoveryActivationPending(ctx)
		if err != nil {
			return err
		}
		if pending {
			return contract.ErrBusy
		}
		return nil
	})
}

// RestoreImport runs independently of the server being stopped. Admission lives
// in the existing import registry until activation writes the ordinary recovery
// journal; after the database switch that journal is the authority.
func RestoreImport(ctx context.Context, directory, id string, service Service) (resultErr error) {
	if service == nil {
		return errors.New("installed service coordinator is unavailable")
	}
	directory, err := backupfs.CanonicalDirectory(directory)
	if err != nil {
		return err
	}
	if _, err := backupfs.ImportPath(id); err != nil {
		return err
	}
	operation, err := acquireRecoveryCaptureLease(ctx, directory)
	if err != nil {
		return err
	}
	defer operation.Close()
	var item backupstore.RecoveryImportRecord
	if err := withRecoveryJobStore(ctx, directory, func(owner *backupstore.Store) error {
		var err error
		item, err = owner.RecoveryImport(ctx, id)
		return err
	}); err != nil {
		return err
	}
	if item.State != "activating" || item.Activation == nil {
		return errors.New("recovery import is not admitted for activation")
	}
	if err := ValidateImportActivation(ctx, item, *item.Activation); err != nil {
		return err
	}
	stopAttempted := false
	defer func() {
		if resultErr == nil {
			return
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
		defer cancel()
		if stopAttempted {
			// Abort/rollback reads the journal before touching SQL: a crash can leave
			// state.db absent or halfway through replacement. Never open/migrate it.
			resultErr = errors.Join(resultErr, recoverImportService(cleanup, directory, id, service))
		} else {
			resultErr = errors.Join(resultErr, resetRecoveryImport(cleanup, directory, id))
		}
	}()
	stopAttempted = true
	if err := service.Stop(ctx); err != nil {
		return err
	}
	result, err := ActivateImport(ctx, directory, item, *item.Activation)
	if err != nil {
		return err
	}
	if err := service.Start(ctx); err != nil {
		return err
	}
	if err := waitImportStartup(ctx, directory, result.TransactionID); err != nil {
		return err
	}
	return cleanupRecoveryImport(directory, id, "")
}

func waitImportStartup(ctx context.Context, directory, id string) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	var previous os.FileInfo
	for {
		info, statErr := os.Lstat(filepath.Join(directory, recoveryJournalName))
		changed := statErr != nil || previous == nil || !os.SameFile(previous, info) || previous.Size() != info.Size() || !previous.ModTime().Equal(info.ModTime())
		if changed {
			tx, err := readRecoveryTransaction(directory)
			if err != nil {
				return err
			}
			if tx != nil {
				if tx.ID != id {
					return errors.New("a different recovery transaction replaced the expected startup")
				}
				if tx.Phase == "committed" {
					return nil
				}
			} else {
				result, err := LastResult(directory)
				if err != nil {
					return err
				}
				if result != nil && result.TransactionID == id {
					if result.State == "committed" {
						return nil
					}
					return errors.New("restored deployment failed startup and rolled back")
				}
				return errors.New("restored deployment lost its pending startup transaction")
			}
			previous = info
		}
		select {
		case <-ctx.Done():
			return errors.New("restored deployment did not complete controlled startup before the deadline")
		case <-tick.C:
		}
	}
}

// RestartImportService is the transient unit's crash/timeout fallback. Holding
// the shared maintenance lease excludes capture/update helpers. An unrelated
// import ID or transaction never grants permission to stop/start the service.
func RestartImportService(ctx context.Context, directory, id string, service Service) error {
	if service == nil {
		return errors.New("installed service coordinator is unavailable")
	}
	directory, err := backupfs.CanonicalDirectory(directory)
	if err != nil {
		return err
	}
	if _, err := backupfs.ImportPath(id); err != nil {
		return err
	}
	lease, err := acquireRecoveryCaptureLease(ctx, directory)
	if err != nil {
		return err
	}
	defer lease.Close()
	return recoverImportService(ctx, directory, id, service)
}

func transactionOwnsImport(tx *recoveryTransaction, id string) bool {
	return tx != nil && filepath.Dir(tx.Stage) == filepath.Join(".recovery-imports", id)
}

func recoverImportService(ctx context.Context, directory, id string, service Service) error {
	tx, err := readRecoveryTransaction(directory)
	if err != nil {
		return err
	}
	if transactionOwnsImport(tx, id) {
		var cleanupErr error
		if tx.Phase != "committed" {
			if err := service.Stop(ctx); err != nil {
				return err
			}
			if err := Rollback(directory, tx.ID, true); err != nil {
				return err
			}
			cleanupErr = resetRecoveryImport(ctx, directory, id)
		} else {
			cleanupErr = cleanupRecoveryImport(directory, id, "")
		}
		// File rollback/commit is authoritative. Cleanup or history failures
		// must not prevent a now-safe deployment from starting again.
		return errors.Join(cleanupErr, service.Start(ctx))
	}
	if tx != nil && tx.Phase != "committed" {
		return errors.New("another recovery transaction owns the deployment")
	}
	var item backupstore.RecoveryImportRecord
	err = withRecoveryJobStore(ctx, directory, func(owner *backupstore.Store) error {
		var err error
		item, err = owner.RecoveryImport(ctx, id)
		return err
	})
	// A successfully committed transaction may already have been retired by
	// another healthy startup. Missing admission is not authority to restart it.
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if item.State != "activating" {
		return nil
	}
	return errors.Join(resetRecoveryImport(ctx, directory, id), service.Start(ctx))
}

func resetRecoveryImport(ctx context.Context, directory, id string) error {
	return withRecoveryJobStore(ctx, directory, func(owner *backupstore.Store) error {
		item, err := owner.RecoveryImport(ctx, id)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if item.State != "activating" {
			return nil
		}
		cleanupErr := cleanupRecoveryImport(directory, id, item.Stage)
		item.State, item.ErrorCode = "failed", "cleanup_failed"
		item.Activation = nil
		if cleanupErr == nil {
			item.State, item.ErrorCode = "uploaded", "activation_failed"
			item.Stage, item.Plan, item.PreviewID = "", "", ""
			item.Preview = nil
		}
		// Keep ownership of plaintext that could not be removed, while
		// releasing the destructive admission after safe file recovery.
		return errors.Join(cleanupErr, owner.SaveRecoveryImport(ctx, item, "activating"))
	})
}

// An empty stage removes the complete expired import after committed activation;
// failure removes plaintext only, retaining the ciphertext for another preview.
func cleanupRecoveryImport(directory, id, stage string) error {
	name, err := backupfs.ImportPath(id)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer root.Close()
	if _, err := backupfs.Destination(root, name, false); err != nil {
		return err
	}
	parent := filepath.Dir(name)
	path := parent
	if stage != "" {
		if filepath.Dir(stage) != parent || !strings.HasPrefix(filepath.Base(stage), ".recovery-stage-") || len(stage) > 128 {
			return errors.New("invalid private recovery staging location")
		}
		path = stage
	}
	if err := root.RemoveAll(path); err != nil {
		return err
	}
	syncParent := filepath.Dir(path)
	if err := backupfs.SyncDirectory(filepath.Join(directory, syncParent)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
