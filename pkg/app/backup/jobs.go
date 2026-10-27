package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"time"
	"uuid"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	contractrecovery "github.com/Asutorufa/yuhaiin/pkg/contract/backup/recovery"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
)

func recoveryS3Digest(options contract.S3) (string, error) {
	data, err := json.Marshal(options)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func (b *Backup) CreateRecoveryBackup(ctx context.Context, request contractrecovery.BackupRequest) (contractrecovery.Backup, error) {
	if b.restoring.Load() {
		return contractrecovery.Backup{}, errBackupBusy
	}
	if b.store == nil {
		return contractrecovery.Backup{}, errors.New("backup store is unavailable")
	}
	if !request.ConfirmMaintenance {
		return contractrecovery.Backup{}, errors.New("full backup requires explicit confirmation of temporary service interruption")
	}
	if !b.mu.TryLock() {
		return contractrecovery.Backup{}, errBackupBusy
	}
	defer func() { b.mu.Unlock(); b.refreshBackupMetrics(ctx) }()
	if b.maintainer == nil {
		return contractrecovery.Backup{}, errors.New("service maintenance is unavailable; use the offline recovery CLI")
	}
	if supported, reason := b.maintainer.Supported(); !supported {
		return contractrecovery.Backup{}, errors.New(reason)
	}
	options, err := b.store.Get(ctx)
	if err != nil {
		return contractrecovery.Backup{}, err
	}
	if options.Recovery == nil {
		return contractrecovery.Backup{}, errors.New("configure full backup encryption first")
	}
	policy, err := backupstore.NormalizeRecoveryPolicy(*options.Recovery)
	if err != nil {
		return contractrecovery.Backup{}, err
	}
	if policy.Recipient == "" || !policy.AllowMaintenance {
		return contractrecovery.Backup{}, errors.New("full backup requires a public recipient and maintenance consent")
	}
	if policy.Target == "s3" && !options.S3.Enabled {
		return contractrecovery.Backup{}, errors.New("full S3 backup requires enabled S3 settings")
	}
	digest, err := recoveryS3Digest(options.S3)
	if err != nil {
		return contractrecovery.Backup{}, err
	}
	job := backupstore.RecoveryJob{
		ID: uuid.New().String(), CreatedAt: time.Now().UTC(), Target: policy.Target, State: "queued", IncludesHistory: policy.IncludeHistory, Policy: policy, S3Digest: digest}
	if err := b.store.EnqueueRecovery(ctx, job); err != nil {
		return contractrecovery.Backup{}, err
	}
	if err := b.maintainer.StartRecovery(ctx, job.ID, time.Duration(policy.TimeoutMinutes)*time.Minute); err != nil {
		job.State, job.ErrorCode, job.CompletedAt = "failed", "maintenance_start_failed", time.Now().UTC()
		// Never include manager/provider output or secret-bearing errors in the
		// durable API record. Preserve the original error only to the caller.
		_ = b.store.SaveRecoveryJob(context.WithoutCancel(ctx), job, "queued")
		return contractrecovery.Backup{}, err
	}
	return job.Backup, nil
}

// resumeRecoveryBackups runs on the existing schedule owner, never an additional
// worker/ticker. Uploads happen after restart through b.proxy and share b.mu with
// legacy/manual backup work. Interrupting a transfer retains the private archive.
func (b *Backup) resumeRecoveryBackups(ctx context.Context) error {
	items, err := b.store.RecoveryPending(ctx)
	if err != nil {
		return err
	}
	// An empty or externally owned capture queue must not contend with manual
	// configuration backups. Only transfer/deletion work needs the shared lease.
	actionable := false
	for _, item := range items {
		if item.State == "deleting" || (item.State == "local_ready" && item.Target == "s3") {
			actionable = true
			break
		}
	}
	if !actionable {
		return nil
	}
	if !b.mu.TryLock() {
		return errBackupBusy
	}
	defer b.mu.Unlock()
	var combined error
	for _, item := range items {
		if err := ctx.Err(); err != nil {
			return errors.Join(combined, err)
		}
		if item.State == "deleting" {
			job, err := b.store.RecoveryJob(ctx, item.ID)
			if err != nil {
				combined = errors.Join(combined, err)
				continue
			}
			if job.State != "deleting" {
				continue
			}
			if err := b.deleteRecoveryBackup(ctx, job); err != nil {
				combined = errors.Join(combined, err)
			}
			continue
		}
		if item.State != "local_ready" || item.Target != "s3" {
			continue
		}
		job, err := b.store.RecoveryJob(ctx, item.ID)
		if err != nil {
			combined = errors.Join(combined, err)
			continue
		}
		if job.State != "local_ready" || job.Target != "s3" {
			continue
		}
		if err := b.uploadRecoveryBackup(ctx, job); err != nil {
			combined = errors.Join(combined, err)
		}
	}
	return combined
}

// A restarted runtime cannot own the previous process's in-flight operation.
// Captures are never adopted without their completed authenticated publication;
// interrupted uploads restart from the unchanged encrypted local archive.
func (b *Backup) recoverInterruptedBackups(ctx context.Context) error {
	if err := b.recoverInterruptedRetrievals(ctx); err != nil {
		return err
	}
	items, err := b.store.RecoveryPending(ctx)
	if err != nil {
		return err
	}
	for _, item := range items {
		if item.State == "local_ready" || item.State == "deleting" {
			continue
		}
		job, err := b.store.RecoveryJob(ctx, item.ID)
		if err != nil {
			return err
		}
		expected := job.State
		if expected == "uploading" {
			job.State, job.ErrorCode = "local_ready", "upload_interrupted"
		} else {
			job.State, job.ErrorCode, job.CompletedAt = "failed", "capture_interrupted", time.Now().UTC()
		}
		if err := b.store.SaveRecoveryJob(ctx, job, expected); err != nil {
			return err
		}
	}
	return nil
}

func validateRecoveryObjectKey(job backupstore.RecoveryJob) error {
	for _, id := range []string{job.BackupID, job.InstanceID} {
		value, err := uuid.Parse(id)
		if err != nil || value == (uuid.UUID{}) || value.String() != id {
			return errors.New("invalid encrypted backup identity")
		}
	}
	if job.ObjectKey != "recovery/"+job.InstanceID+"/"+job.BackupID+".yhb" {
		return errors.New("backup object key does not match its owned namespace")
	}
	return nil
}

func (b *Backup) RetryRecoveryBackup(ctx context.Context, id string) error {
	if b.store == nil {
		return errors.New("backup store is unavailable")
	}
	if !b.mu.TryLock() {
		return errBackupBusy
	}
	defer func() { b.mu.Unlock(); b.refreshBackupMetrics(ctx); b.reschedule() }()
	job, err := b.store.RecoveryJob(ctx, id)
	if err != nil {
		return err
	}
	if job.State != "failed" || job.Target != "s3" || job.BackupID == "" {
		return errors.New("only failed uploads of completed encrypted archives can be retried")
	}
	job.State, job.ErrorCode, job.UploadAttempts = "local_ready", "", 0
	return b.store.SaveRecoveryJob(ctx, job, "failed")
}
