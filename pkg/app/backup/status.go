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
	}
	return out, err
}

// RecoveryRestoreStatus reads the durable transaction result through its owner.
func (b *Backup) RecoveryRestoreStatus(ctx context.Context) (contract.RecoveryRestoreStatus, error) {
	return recovery.RestoreStatus(ctx, b.dir)
}
