package backup

import (
	"context"
	"errors"
	"github.com/Asutorufa/yuhaiin/pkg/update/maintenance"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lockfile"
	"os"
	"path/filepath"
	"time"

	backupfs "github.com/Asutorufa/yuhaiin/pkg/app/backup/internal/backupfs"
	"github.com/Asutorufa/yuhaiin/pkg/s3"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
)

func (b *Backup) DeleteRecoveryBackup(ctx context.Context, id string) error {
	if b.store == nil {
		return errors.New("backup store is unavailable")
	}
	ctx, cancel := b.operationContext(ctx)
	defer cancel()
	if !b.mu.TryLock() {
		return errBackupBusy
	}
	defer func() { b.mu.Unlock(); b.refreshBackupMetrics(ctx) }()
	job, err := b.store.RecoveryJob(ctx, id)
	if err != nil {
		return err
	}
	return b.deleteRecoveryBackup(ctx, job)
}

func (b *Backup) deleteRecoveryBackup(ctx context.Context, job backupstore.RecoveryJob) (resultErr error) {
	lease, err := lockfile.Acquire(filepath.Join(b.dir, ".recovery-maintenance.lock"))
	if err != nil {
		return errBackupBusy
	}
	defer lease.Close()
	protected, err := maintenance.ActiveBackup(b.dir)
	if err != nil {
		return err
	}
	if protected == job.ID {
		return errors.New("update recovery point is still required; complete or recover the update first")
	}

	if job.State == "deleting" && job.DeleteFrom != "verified" && job.DeleteFrom != "local_ready" && job.DeleteFrom != "failed" {
		return errors.New("invalid interrupted backup deletion")
	}
	if b.recoveryReaders[job.ID] > 0 {
		return errors.New("backup download is active; retry deletion after it closes")
	}
	if job.State != "deleting" {
		if job.State != "verified" && job.State != "local_ready" && job.State != "failed" {
			return errors.New("active backup cannot be deleted")
		}
		// local_ready S3 data is an upload queue item, not a retained success.
		if job.State == "local_ready" && job.Target == "s3" {
			return errors.New("pending S3 upload cannot be deleted")
		}
		job.DeleteFrom, job.State = job.State, "deleting"
		if err := b.store.SaveRecoveryJob(ctx, job, job.DeleteFrom); err != nil {
			return err
		}
	}
	defer func() {
		if resultErr != nil {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			job.State, job.ErrorCode = job.DeleteFrom, "retention_failed"
			_ = b.store.SaveRecoveryJob(cleanup, job, "deleting")
		}
	}()
	if job.Target == "s3" && job.ObjectKey != "" {
		options, err := b.store.Get(ctx)
		if err != nil {
			return err
		}
		digest, err := recoveryS3Digest(options.S3)
		if err != nil {
			return err
		}
		if digest != job.S3Digest {
			return errors.New("S3 destination changed; original object cannot be safely removed")
		}
		if err := validateRecoveryObjectKey(job); err != nil {
			return err
		}
		client, err := s3.NewS3(options.S3, b.proxy)
		if err != nil {
			return err
		}
		defer client.Close()
		if err := client.Delete(ctx, job.ObjectKey); err != nil {
			return err
		}
	}
	path, err := backupfs.ArchivePath(b.dir, job.ID)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(b.dir)
	if err != nil {
		return err
	}
	defer root.Close()
	relative, err := filepath.Rel(b.dir, path)
	if err != nil {
		return err
	}
	exists, err := backupfs.Destination(root, relative, false)
	if err != nil {
		return err
	}
	if exists {
		if err := root.Remove(relative); err != nil {
			return err
		}
	}
	// A crash between file/object removal and this metadata deletion is resumed
	// from state=deleting. Neither stage can select an unrelated file or bucket.
	return b.store.DeleteRecoveryJob(ctx, job.ID)
}

// Retention reads its plan without taking the transfer lease. Only actual
// deletion work competes with manual control requests, and the plan is reloaded
// under the lease before any side effects.
func (b *Backup) pruneRecoveryBackups(ctx context.Context) error {
	ids, err := b.recoveryRetentionPlan(ctx)
	if err != nil || len(ids) == 0 {
		return err
	}
	if !b.mu.TryLock() {
		return errBackupBusy
	}
	defer b.mu.Unlock()
	ids, err = b.recoveryRetentionPlan(ctx)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if b.recoveryReaders[id] > 0 {
			continue
		}
		job, err := b.store.RecoveryJob(ctx, id)
		if err != nil {
			return err
		}
		if err := b.deleteRecoveryBackup(ctx, job); err != nil {
			return err
		}
	}
	return nil
}

func (b *Backup) recoveryRetentionPlan(ctx context.Context) ([]string, error) {
	options, err := b.store.Get(ctx)
	if err != nil || options.Recovery == nil {
		return nil, err
	}
	policy, err := backupstore.NormalizeRecoveryPolicy(*options.Recovery)
	if err != nil {
		return nil, err
	}
	items, err := b.store.RecoveryRetentionCandidates(ctx)
	if err != nil {
		return nil, err
	}
	protected, err := maintenance.ActiveBackup(b.dir)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	var ids []string
	successful := 0
	for _, item := range items {
		if item.ID == protected {
			continue
		}
		ready := item.State == "verified" || (item.State == "local_ready" && item.Target == "local")
		if !ready && item.State != "failed" {
			continue
		}
		if ready {
			successful++
			// Keep the latest successful point even when every point is old.
			if successful == 1 {
				continue
			}
		}
		expired := now.Sub(item.CreatedAt) > time.Duration(policy.KeepDays)*24*time.Hour
		excess := ready && successful > policy.KeepCount
		if expired || excess {
			ids = append(ids, item.ID)
		}
	}
	return ids, nil
}
