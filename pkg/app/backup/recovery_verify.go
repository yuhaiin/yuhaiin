package backup

import (
	"context"
	"errors"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
)

func (b *Backup) VerifyRecoveryBackup(ctx context.Context, request contract.RecoveryVerifyRequest) (contract.RecoveryManifest, error) {
	var empty contract.RecoveryManifest
	if b.store == nil {
		return empty, errors.New("backup store is unavailable")
	}
	if !b.mu.TryLock() {
		return empty, errBackupBusy
	}
	defer func() { b.mu.Unlock(); b.refreshBackupMetrics(ctx); b.reschedule() }()
	job, err := b.store.RecoveryJob(ctx, request.ID)
	if err != nil {
		return empty, err
	}
	if job.State != "verified" && job.State != "local_ready" {
		return empty, errors.New("backup is not ready for verification")
	}
	policy, err := backupstore.NormalizeRecoveryPolicy(job.Policy)
	if err != nil {
		return empty, err
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(policy.TimeoutMinutes)*time.Minute)
	defer cancel()
	if b.ctx != nil {
		stop := context.AfterFunc(b.ctx, cancel)
		defer stop()
		if b.ctx.Err() != nil {
			cancel()
		}
	}
	file, err := openManagedRecoveryArchive(b.dir, request.ID)
	if err != nil {
		return empty, err
	}
	defer file.Close()
	size, digest, digestErr := digestRecoveryArchiveFile(ctx, file)
	var prepared *backupstore.PreparedRecovery
	verifyErr := digestErr
	if verifyErr == nil && (size != job.Size || digest != job.SHA256) {
		verifyErr = errors.New("encrypted archive differs from its recorded digest")
	}
	if verifyErr == nil {
		prepared, verifyErr = backupstore.PrepareRecoveryArchive(ctx, file, b.dir, backupstore.RecoveryDecryption{Identity: request.Identity, Passphrase: request.Passphrase})
	}
	job.ArchiveCheck, job.ArchiveCheckedAt = "passed", time.Now().UTC()
	if verifyErr != nil {
		job.ArchiveCheck = "failed"
	} else {
		defer prepared.Close()
		if prepared.Manifest.ID != job.BackupID || prepared.Manifest.InstanceID != job.InstanceID || !prepared.Manifest.CompleteInventory {
			verifyErr = errors.New("archive identity differs from its recorded backup")
			job.ArchiveCheck = "failed"
		}
	}
	if ctx.Err() != nil {
		job.ArchiveCheck = "cancelled"
	}
	recordCtx, recordCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer recordCancel()
	if err := b.store.SaveRecoveryJob(recordCtx, job, job.State); err != nil {
		return empty, err
	}
	if ctx.Err() != nil {
		return empty, ctx.Err()
	}
	if verifyErr != nil {
		// Do not expose decryption-library errors containing user key material.
		return empty, errors.New("archive authentication failed; check the private key/passphrase and archive integrity")
	}
	return prepared.Manifest, nil
}
