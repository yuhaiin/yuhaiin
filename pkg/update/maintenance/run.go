package maintenance

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/app/backup/recovery"
	"github.com/Asutorufa/yuhaiin/pkg/update/compatibility"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lockfile"
)

// Host is the installed-service adapter. Preserve uses the existing executable
// history; health receipts are produced by the real application, not Start().
type Host interface {
	Stop(context.Context) error
	Start(context.Context) error
	MainPID(context.Context) (int, error)
	ConfirmReady(context.Context, Record) error
	Preserve(context.Context, Record) error
	Prune(context.Context, Record) error
}

func verify(ctx context.Context, path string, m compatibility.Manifest) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() != m.Size {
		return errors.New("update executable type or size changed")
	}
	observed, err := compatibility.Describe(ctx, path, m.Platform, m.Architecture)
	if err != nil || observed.SHA256 != m.SHA256 {
		return errors.New("update executable checksum changed")
	}
	return m.VerifyPlatform(path)
}

func Run(ctx context.Context, directory, id string, host Host) (resultErr error) {
	if host == nil {
		return errors.New("update service host is unavailable")
	}
	owner, err := lockfile.Acquire(filepath.Join(directory, ".recovery-maintenance.lock"))
	if err != nil {
		return err
	}
	defer owner.Close()
	record, err := Read(directory)
	if err != nil {
		return err
	}
	if record == nil || record.ID != id || record.Phase != "prepared" || record.Target.UpdateGuard != 1 {
		return errors.New("update is not admitted for maintenance")
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
		defer cancel()
		if resultErr != nil {
			resultErr = errors.Join(resultErr, recoverOperation(cleanup, directory, id, host))
		}
		_ = os.Remove(record.StagedPath)
		_ = os.Remove(record.StagedPath + compatibility.Suffix)
	}()
	if err := recovery.GuardServiceMaintenance(ctx, directory); err != nil {
		return err
	}
	if err := verify(ctx, record.TargetPath, record.Source); err != nil {
		return err
	}
	if err := verify(ctx, record.StagedPath, record.Target); err != nil {
		return err
	}
	status, err := record.Target.Check(ctx, directory)
	if err != nil {
		return err
	}
	if status.State != "compatible" && (status.State != "migration_required" || record.BackupJobID == "") {
		return errors.New("update target is incompatible with deployment")
	}
	if err := host.Stop(ctx); err != nil {
		return err
	}
	if record.BackupJobID != "" {
		if err := SetPhase(ctx, directory, id, "capturing", ""); err != nil {
			return err
		}
		if err := recovery.CaptureStopped(ctx, directory, record.BackupJobID, owner); err != nil {
			return err
		}
		point, err := recovery.CompletedCapture(ctx, directory, record.BackupJobID)
		if err != nil {
			return err
		}
		if err := change(ctx, directory, id, func(r *Record) error {
			r.BackupID = point.BackupID
			r.SourceInstanceID = point.InstanceID
			r.Phase = "backup_ready"
			return nil
		}); err != nil {
			return err
		}
	} else if err := SetPhase(ctx, directory, id, "backup_ready", ""); err != nil {
		return err
	}
	record, err = Read(directory)
	if err != nil {
		return err
	}
	// Re-read closed owners after capture, before any executable rename.
	status, err = record.Target.Check(ctx, directory)
	if err != nil {
		return err
	}
	if status.State != "compatible" && (status.State != "migration_required" || record.BackupID == "") {
		return errors.New("database schema changed during update preparation")
	}
	if err := verify(ctx, record.TargetPath, record.Source); err != nil {
		return err
	}
	if err := host.Preserve(ctx, *record); err != nil {
		return err
	}
	if err := verify(ctx, record.StagedPath, record.Target); err != nil {
		return err
	}
	if err := verify(ctx, record.TargetPath, record.Source); err != nil {
		return err
	}
	if err := SetPhase(ctx, directory, id, "swapping", ""); err != nil {
		return err
	}
	if err := swapExecutable(*record); err != nil {
		return err
	}
	// Persist before Start: even an ambiguous start can have migrated databases.
	if err := SetPhase(ctx, directory, id, "starting", ""); err != nil {
		return err
	}
	if err := host.Start(ctx); err != nil {
		return err
	}
	if err := waitReady(ctx, directory, id, host); err != nil {
		return err
	}
	if err := SetPhase(ctx, directory, id, "completed", ""); err != nil {
		return err
	}
	// A committed healthy deployment is never undone for retention/history errors.
	_ = host.Prune(ctx, *record)
	_ = os.Remove(record.TargetPath + ".update-backup")
	return nil
}

func swapExecutable(r Record) error {
	parent := filepath.Dir(r.TargetPath)
	root, err := os.OpenRoot(parent)
	if err != nil {
		return err
	}
	defer root.Close()
	target, stage := filepath.Base(r.TargetPath), filepath.Base(r.StagedPath)
	backup := target + ".update-backup"
	if _, err := root.Lstat(backup); err == nil {
		return errors.New("an existing update executable recovery copy requires review")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := root.Rename(target, backup); err != nil {
		return err
	}
	if err := syncDirectory(parent); err != nil {
		return err
	}
	if err := root.Rename(stage, target); err != nil {
		return err
	}
	if err := root.Chmod(target, 0755); err != nil {
		return err
	}
	return syncDirectory(parent)
}

func waitReady(ctx context.Context, directory, id string, host Host) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		r, err := Read(directory)
		if err != nil {
			return err
		}
		if r == nil || r.ID != id {
			return errors.New("update operation changed during startup")
		}
		if r.Phase == "healthy" && r.ReadyPID > 0 && !r.ReadyAt.IsZero() {
			pid, err := host.MainPID(ctx)
			if err == nil && pid == r.ReadyPID && host.ConfirmReady(ctx, *r) == nil {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// Recover is the independent ExecStopPost fallback. The maintenance lease makes
// cleanup idempotent and excludes another restore/capture/update owner.
func Recover(ctx context.Context, directory, id string, host Host) error {
	owner, err := lockfile.Acquire(filepath.Join(directory, ".recovery-maintenance.lock"))
	if err != nil {
		return err
	}
	defer owner.Close()
	if err := recoverOperation(ctx, directory, id, host); err != nil {
		return err
	}
	r, err := Read(directory)
	if err != nil || r == nil || r.ID != id || !Terminal(r.Phase) {
		return err
	}
	_ = os.Remove(r.StagedPath)
	_ = os.Remove(r.StagedPath + compatibility.Suffix)
	return nil
}
func recoverOperation(ctx context.Context, directory, id string, host Host) error {
	r, err := Read(directory)
	if err != nil {
		return err
	}
	if r == nil || r.ID != id {
		return errors.New("update recovery operation changed")
	}
	if Terminal(r.Phase) {
		return nil
	}
	if r.Phase == "starting" || r.Phase == "healthy" {
		stopErr := host.Stop(ctx)
		// Never run the source binary after the target may have opened its stores.
		code := "startup_failed_restore_point_required"
		if r.BackupJobID == "" {
			code = "startup_failed_no_recovery_point"
		}
		markErr := SetPhase(ctx, directory, id, "manual_recovery", code)
		return errors.Join(stopErr, markErr)
	}
	if r.Phase == "swapping" {
		backup := r.TargetPath + ".update-backup"
		if _, err := os.Lstat(backup); err == nil {
			if err := verify(ctx, backup, r.Source); err != nil {
				return err
			}
			// A crash can leave either a missing destination or the reviewed target.
			// Never overwrite an operator replacement, directory or symbolic link.
			if _, err := os.Lstat(r.TargetPath); err == nil {
				if err := verify(ctx, r.TargetPath, r.Target); err != nil {
					return errors.Join(errors.New("installed executable changed during recovery; preserve it for offline review"), SetPhase(ctx, directory, id, r.Phase, "executable_changed_review_required"))
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
			if err := os.Rename(backup, r.TargetPath); err != nil {
				return err
			}
			if err := syncDirectory(filepath.Dir(r.TargetPath)); err != nil {
				return err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := verify(ctx, r.TargetPath, r.Source); err != nil {
		return errors.Join(err, SetPhase(ctx, directory, id, r.Phase, "executable_changed_review_required"))
	}
	if r.BackupJobID != "" {
		_ = recovery.FailCapture(ctx, directory, r.BackupJobID, "update_preparation_failed")
	}
	if err := SetPhase(ctx, directory, id, "failed", "preparation_failed_source_preserved"); err != nil {
		return err
	}
	return host.Start(ctx)
}
