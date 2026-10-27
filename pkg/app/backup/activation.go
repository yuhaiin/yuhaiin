package backup

import (
	"context"
	"errors"
	"github.com/Asutorufa/yuhaiin/pkg/update/maintenance"
	"path/filepath"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/app/backup/recovery"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lockfile"
)

// ActivateRecoveryImport persists exact-preview consent before handing off to
// the independent installed-service supervisor. No database files are replaced
// from a request handler or a runtime-owned background goroutine.
func (b *Backup) ActivateRecoveryImport(ctx context.Context, request contract.RecoveryImportActivateRequest) (contract.RecoveryImport, error) {
	var empty contract.RecoveryImport
	if b.store == nil {
		return empty, errors.New("backup store is unavailable")
	}
	if !b.mu.TryLock() {
		return empty, errBackupBusy
	}
	defer b.mu.Unlock()
	item, err := b.store.RecoveryImport(ctx, request.ID)
	if err != nil {
		return empty, err
	}
	if item.Owner != recoveryImportOwner(ctx) {
		return empty, errors.New("recovery import is unavailable")
	}
	if err := recovery.ValidateImportActivation(ctx, item, request); err != nil {
		return empty, err
	}
	if item.State == "activating" {
		if item.Activation == nil || *item.Activation != request {
			return empty, errors.New("another activation request owns this preview")
		}
		return item.RecoveryImport, nil
	}
	if b.restoring.Load() {
		return empty, errBackupBusy
	}
	restorer, ok := b.maintainer.(RecoveryRestorer)
	if !ok {
		return empty, errors.New("installed-service restore supervision is unavailable; use offline recovery")
	}
	if supported, reason := b.maintainer.Supported(); !supported {
		return empty, errors.New(reason)
	}
	// Serialize handoff publication with update/capture helpers, not just their
	// later execution. An update that wins first cannot leave a queued restore
	// helper running old code against a newly replaced executable/schema.
	lease, err := lockfile.Acquire(filepath.Join(b.dir, ".recovery-maintenance.lock"))
	if err != nil {
		return empty, errBackupBusy
	}
	defer lease.Close()
	if err := maintenance.GuardAdmission(b.dir); err != nil {
		return empty, err
	}
	item.State, item.Activation, item.ErrorCode = "activating", new(request), ""
	if err := b.store.AdmitRecoveryImport(ctx, item); err != nil {
		return empty, err
	}
	b.restoring.Store(true)
	b.reschedule()
	// A launch timeout can race a successfully started helper. Leave the durable
	// admission intact on error: retry returns the same operation, while discard
	// may cancel it only after taking the same maintenance lease as that helper.
	if err := restorer.StartRestore(ctx, item.ID, 10*time.Minute); err != nil {
		item.ErrorCode = "launch_uncertain"
		recordCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		_ = b.store.SaveRecoveryImport(recordCtx, item, "activating")
		// The durable decision was accepted even if unit launch is uncertain.
		// Returning a generic rejection would hide a possibly running restore.
		return item.RecoveryImport, nil
	}
	return item.RecoveryImport, nil
}
