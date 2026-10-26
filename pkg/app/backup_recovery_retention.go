package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/s3"
	"github.com/Asutorufa/yuhaiin/pkg/store"
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

func (b *Backup) deleteRecoveryBackup(ctx context.Context, job store.RecoveryJob) (resultErr error) {
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
	path, err := recoveryArchivePath(b.dir, job.ID)
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
	exists, err := recoveryDestination(root, relative, false)
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

// Retention runs only after a completed backup, never on an idle polling timer.
// Failed attempts do not consume the count of retained successful points.
func (b *Backup) pruneRecoveryBackups(ctx context.Context) error {
	// Preserve legacy manual-backup admission when full backups are unused.
	options, err := b.store.Get(ctx)
	if err != nil || options.Recovery == nil {
		return err
	}
	if !b.mu.TryLock() {
		return errBackupBusy
	}
	defer b.mu.Unlock()
	options, err = b.store.Get(ctx)
	if err != nil {
		return err
	}
	if options.Recovery == nil {
		return nil
	}
	policy, err := store.NormalizeRecoveryPolicy(*options.Recovery)
	if err != nil {
		return err
	}
	items, err := b.store.RecoveryRetentionCandidates(ctx)
	if err != nil {
		return err
	}
	successful := 0
	for _, item := range items {
		ready := item.State == "verified" || (item.State == "local_ready" && item.Target == "local")
		if !ready && item.State != "failed" {
			continue
		}
		if ready {
			successful++
			// Preserve the latest successful recovery point even when every
			// point is old. Explicit administrator deletion remains possible.
			if successful == 1 {
				continue
			}
		}
		expired := time.Since(item.CreatedAt) > time.Duration(policy.KeepDays)*24*time.Hour
		excess := ready && successful > policy.KeepCount
		if !expired && !excess {
			continue
		}
		if b.recoveryReaders[item.ID] > 0 {
			continue
		}
		job, err := b.store.RecoveryJob(ctx, item.ID)
		if err != nil {
			return err
		}
		if err := b.deleteRecoveryBackup(ctx, job); err != nil {
			return err
		}
	}
	return nil
}
