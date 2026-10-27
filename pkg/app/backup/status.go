package backup

import (
	"context"
	"errors"

	"github.com/Asutorufa/yuhaiin/pkg/app/backup/recovery"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
)

func (b *Backup) RecoveryBackups(ctx context.Context) (contract.RecoveryBackupStatus, error) {
	out := contract.RecoveryBackupStatus{Items: []contract.RecoveryBackup{}}
	if b.store == nil {
		return out, errors.New("backup store is unavailable")
	}
	if b.maintainer != nil {
		out.Supported, out.Reason = b.maintainer.Supported()
	} else {
		out.Reason = "full backup maintenance requires an installed service; use the offline recovery CLI"
	}
	version := b.metricsVersion.Add(1)
	var err error
	out.Items, err = b.store.RecoveryHistory(ctx)
	if err == nil {
		b.compileBackupMetrics(version, out.Items)
		for i := range out.Items {
			out.Items[i].LocalState = localRecoveryArchiveState(b.dir, out.Items[i])
		}
	}
	return out, err
}

// RecoveryRestoreStatus reads the durable transaction result through its owner.
func (b *Backup) RecoveryRestoreStatus(ctx context.Context) (contract.RecoveryRestoreStatus, error) {
	actual, actualErr := recovery.RestoreStatus(ctx, b.dir)
	if b.store != nil {
		ids, err := b.store.RecoveryImportIDs(ctx)
		if err != nil {
			return contract.RecoveryRestoreStatus{}, err
		}
		for _, id := range ids {
			item, err := b.store.RecoveryImport(ctx, id)
			if err != nil {
				return contract.RecoveryRestoreStatus{}, err
			}
			if item.State == "activating" {
				if actualErr == nil && actual.Result != nil && actual.Result.TransactionID == item.PreviewID {
					if b.restoring.CompareAndSwap(true, false) {
						b.reschedule()
					}
					return actual, nil
				}
				return contract.RecoveryRestoreStatus{PendingImportID: item.ID, PendingPreviewID: item.PreviewID}, nil
			}
		}
		if b.restoring.CompareAndSwap(true, false) {
			b.reschedule()
		}
	}
	return actual, actualErr
}
