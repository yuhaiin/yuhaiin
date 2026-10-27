package backup

import (
	"context"
	"errors"
	"time"

	contractrecovery "github.com/Asutorufa/yuhaiin/pkg/contract/backup/recovery"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
)

// reschedule cancels periodic work without waiting for an upload while holding
// a settings lock. One owner goroutine manages the only scheduling timer.
func (b *Backup) reschedule() {
	b.scheduleMu.Lock()
	if b.scheduledCancel != nil {
		b.scheduledCancel()
	}
	select {
	case b.changed <- struct{}{}:
	default:
	}
	b.scheduleMu.Unlock()
}
func (b *Backup) schedule() {
	defer close(b.done)
	for {
		if b.restoring.Load() {
			timer := time.NewTimer(time.Minute)
			select {
			case <-b.ctx.Done():
				timer.Stop()
				return
			case <-b.changed:
			case <-timer.C:
				// A failed helper can leave the original process alive. Reconcile
				// its completed admission without depending on an open browser.
				_, _ = b.RecoveryRestoreStatus(b.ctx)
			}
			timer.Stop()
			continue
		}
		retry := false
		if b.store != nil {
			if err := b.pruneRecoveryImports(b.ctx); err != nil && b.ctx.Err() == nil {
				retry = true
				if !errors.Is(err, errBackupBusy) {
					log.Warn("recovery import cleanup failed")
				}
			}
			if err := b.resumeRecoveryBackups(b.ctx); err != nil && b.ctx.Err() == nil {
				retry = true
				if !errors.Is(err, errBackupBusy) {
					log.Warn("full backup upload did not complete; consult backup history")
				}
			}
			if err := b.pruneRecoveryBackups(b.ctx); err != nil && b.ctx.Err() == nil {
				retry = true
				if !errors.Is(err, errBackupBusy) {
					log.Warn("backup retention did not complete; consult backup history")
				}
			}
			b.refreshBackupMetrics(b.ctx)
		}
		var tick <-chan time.Time
		var timer *time.Timer
		full := false
		recheck := false
		if b.store != nil {
			opt, err := b.store.Get(b.ctx)
			if err == nil && opt.Recovery != nil {
				policy, policyErr := backupstore.NormalizeRecoveryPolicy(*opt.Recovery)
				if policyErr != nil {
					opt.Recovery = nil
				} else {
					opt.Recovery = &policy
				}
			}
			var delay time.Duration
			if err == nil && opt.Recovery != nil && opt.Recovery.Enabled && b.maintainer != nil {
				if supported, _ := b.maintainer.Supported(); supported {
					last, lastErr := b.store.LastRecoveryAttempt(b.ctx)
					if lastErr == nil {
						if last.IsZero() || last.After(time.Now()) {
							last = b.scheduleStarted
						}
						delay = time.Duration(opt.Recovery.IntervalMinutes) * time.Minute
						delay = max(time.Until(last.Add(delay)), time.Millisecond)
						full = true
					} else {
						err = lastErr
					}
				} else {
					// Service-manager state can change independently of settings.
					// Re-evaluate it without launching a configuration backup.
					recheck = true
					delay = time.Minute
				}
			}
			if err == nil && opt.S3.Enabled && opt.Interval > 0 && opt.Interval <= 365*24*60 {
				legacyDelay := time.Duration(opt.Interval) * time.Minute
				if delay == 0 || legacyDelay < delay || (recheck && legacyDelay == delay) {
					delay = legacyDelay
					full = false
					recheck = false
				}
			}
			if expiry, expiryErr := b.store.NextRecoveryImportExpiry(b.ctx); expiryErr != nil {
				err = errors.Join(err, expiryErr)
			} else if !expiry.IsZero() {
				expiryDelay := max(time.Until(expiry), time.Minute)
				if delay == 0 || expiryDelay < delay {
					delay, recheck = expiryDelay, true
				}
			}
			// Pending work must not lose its only wakeup when a manual operation
			// owns the lease. Reuse this timer for a bounded fallback recheck.
			if retry && (delay == 0 || time.Minute < delay) {
				delay, recheck = time.Minute, true
			}
			if err != nil && b.ctx.Err() == nil {
				timer = time.NewTimer(time.Minute)
				tick = timer.C
				recheck = true
			} else if delay > 0 {
				timer = time.NewTimer(delay)
				tick = timer.C
			}

		}
		select {
		case <-b.ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return
		case <-b.changed:
			if timer != nil {
				timer.Stop()
			}
			continue
		case <-tick:
		}
		if recheck {
			continue
		}
		ctx, cancel := context.WithTimeout(b.ctx, 10*time.Minute)
		b.scheduleMu.Lock()
		select {
		case <-b.changed:
			b.scheduleMu.Unlock()
			cancel()
			continue
		default:
		}
		b.scheduledCancel = cancel
		b.scheduleMu.Unlock()
		var operationErr error
		if full {
			_, operationErr = b.CreateRecoveryBackup(ctx, contractrecovery.BackupRequest{ConfirmMaintenance: true})
		} else {
			operationErr = b.Run(ctx)
		}
		if operationErr != nil && ctx.Err() == nil && !errors.Is(operationErr, errBackupBusy) {
			log.Warn("scheduled backup did not complete; consult backup history")
		}
		cancel()
		b.scheduleMu.Lock()
		b.scheduledCancel = nil
		b.scheduleMu.Unlock()
	}
}
