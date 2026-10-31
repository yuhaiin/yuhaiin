package recovery

import (
	"context"
	"errors"
	"time"

	contractrecovery "github.com/Asutorufa/yuhaiin/pkg/contract/backup/recovery"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
)

func CompletedCapture(ctx context.Context, directory, id string) (contractrecovery.Backup, error) {
	var result contractrecovery.Backup
	err := withRecoveryJobStore(ctx, directory, func(owner *backupstore.Store) error {
		job, err := owner.RecoveryJob(ctx, id)
		if err != nil {
			return err
		}
		if !job.UpdatePoint || (job.State != "local_ready" && job.State != "verified") || job.BackupID == "" || job.Size < 1 || job.SHA256 == "" {
			return errors.New("update recovery archive was not completed")
		}
		result = job.Backup
		return nil
	})
	return result, err
}
func FailCapture(ctx context.Context, directory, id, code string) error {
	return withRecoveryJobStore(ctx, directory, func(owner *backupstore.Store) error {
		job, err := owner.RecoveryJob(ctx, id)
		if err != nil {
			return err
		}
		if job.State != "queued" && job.State != "capturing" {
			return nil
		}
		expected := job.State
		job.State, job.ErrorCode, job.CompletedAt = "failed", code, time.Now().UTC()
		return owner.SaveRecoveryJob(ctx, job, expected)
	})
}
