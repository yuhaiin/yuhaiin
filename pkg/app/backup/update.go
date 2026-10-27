package backup

import (
	"context"
	"errors"
	"time"
	"uuid"

	"github.com/Asutorufa/yuhaiin/pkg/app/backup/internal/backupfs"
	contractrecovery "github.com/Asutorufa/yuhaiin/pkg/contract/backup/recovery"
	updatecontract "github.com/Asutorufa/yuhaiin/pkg/contract/update"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
)

func (b *Backup) UpdateRecoveryReadiness(ctx context.Context) (updatecontract.RecoveryReadiness, error) {
	result := updatecontract.RecoveryReadiness{Enabled: true, Reason: "configure_encrypted_backup"}
	if b.store == nil {
		return result, errors.New("backup store is unavailable")
	}
	options, err := b.store.Get(ctx)
	if err != nil {
		return result, err
	}
	if options.Recovery != nil && options.Recovery.ProtectUpdates != nil && !*options.Recovery.ProtectUpdates {
		result.Enabled = false
		result.Ready = true
		result.Reason = "disabled_by_administrator"
		return result, nil
	}
	if b.maintainer == nil {
		return result, nil
	}
	result.Supported, result.Reason = b.maintainer.Supported()
	if !result.Supported {
		return result, nil
	}
	if options.Recovery == nil {
		result.Reason = "configure_encrypted_backup"
		return result, nil
	}
	policy, err := backupstore.NormalizeRecoveryPolicy(*options.Recovery)
	if err != nil {
		return result, err
	}
	if policy.Recipient == "" || !policy.AllowMaintenance {
		result.Reason = "configure_encrypted_backup"
		return result, nil
	}
	if policy.Target == "s3" && !options.S3.Enabled {
		result.Reason = "enable_s3"
		return result, nil
	}
	result.Ready, result.Reason = true, "ready"
	return result, nil
}

// QueueUpdateRecovery registers the same immutable encrypted backup request but
// leaves execution to the already-independent update maintenance owner.
func (b *Backup) QueueUpdateRecovery(ctx context.Context) (contractrecovery.Backup, error) {
	var empty contractrecovery.Backup
	if !b.mu.TryLock() {
		return empty, errBackupBusy
	}
	defer b.mu.Unlock()
	if b.restoring.Load() {
		return empty, errBackupBusy
	}
	ready, err := b.UpdateRecoveryReadiness(ctx)
	if err != nil {
		return empty, err
	}
	if !ready.Enabled || !ready.Ready {
		return empty, errors.New("encrypted update recovery point is not ready")
	}
	if err := backupfs.CheckStagingSpace(b.dir, 0); err != nil {
		return empty, err
	}
	options, err := b.store.Get(ctx)
	if err != nil {
		return empty, err
	}
	policy, err := backupstore.NormalizeRecoveryPolicy(*options.Recovery)
	if err != nil {
		return empty, err
	}
	// An update recovery point keeps business history as well as mandatory quota
	// and identity state, so a failed update can restore the complete prior set.
	policy.IncludeHistory = true
	digest, err := recoveryS3Digest(options.S3)
	if err != nil {
		return empty, err
	}
	job := backupstore.RecoveryJob{ID: uuid.New().String(), CreatedAt: time.Now().UTC(), Target: policy.Target, State: "queued", IncludesHistory: true, Policy: policy, S3Digest: digest, UpdatePoint: true}
	if err := b.store.EnqueueRecovery(ctx, job); err != nil {
		return empty, err
	}
	return job.Backup, nil
}

func (b *Backup) CancelUpdateRecovery(ctx context.Context, id string) error {
	if !b.mu.TryLock() {
		return errBackupBusy
	}
	defer b.mu.Unlock()

	if b.store == nil {
		return errors.New("backup store is unavailable")
	}
	job, err := b.store.RecoveryJob(ctx, id)
	if err != nil {
		return err
	}
	if !job.UpdatePoint || job.State != "queued" {
		return nil
	}
	job.State, job.ErrorCode, job.CompletedAt = "failed", "update_not_started", time.Now().UTC()
	return b.store.SaveRecoveryJob(ctx, job, "queued")
}
