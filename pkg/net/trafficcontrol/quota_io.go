package trafficcontrol

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol/quota"
)

// A stream holds at most one 16 KiB reservation while pacing/writing. Upload
// reservations begin after reading client bytes, so idle reads reserve nothing.
func (p Policy) reserveQuota(ctx context.Context, d Direction, size int, ticket *quota.Reservation, deadline *streamDeadline) (int, bool, error) {
	for {
		if err := ctx.Err(); err != nil {
			return 0, false, err
		}
		plan, changed, err := p.quotaState()
		if err != nil {
			return 0, false, err
		}
		if plan == nil {
			return min(size, 16<<10), false, nil
		}
		n, ready, err := plan.TryReserve(time.Now(), quota.Direction(d), min(size, 16<<10), false, ticket)
		if err == nil {
			return n, true, nil
		}
		if errors.Is(err, quota.ErrRetired) {
			if err := waitQuota(ctx, deadline, nil, changed, plan.ExpiresAt()); err != nil {
				return 0, false, err
			}
			continue
		}
		if errors.Is(err, quota.ErrExhausted) {
			p.recordRejection(rejectQuota)
			effects, effectErr := plan.Effects(time.Now())
			if effectErr != nil {
				return 0, false, effectErr
			}
			if effects.Terminate {
				return 0, false, err
			}
		} else if !errors.Is(err, quota.ErrFunding) && !errors.Is(err, quota.ErrExpired) && !errors.Is(err, quota.ErrBusy) {
			return 0, false, err
		} else {
			p.recordRejection(rejectQuotaCredit)
		}
		reset := plan.ExpiresAt()
		if errors.Is(err, quota.ErrBusy) {
			reset = time.Now().Add(time.Second).Unix()
		}
		if err := waitQuota(ctx, deadline, ready, changed, reset); err != nil {
			return 0, false, err
		}
	}
}

func waitQuota(ctx context.Context, deadline *streamDeadline, ready, changed <-chan struct{}, reset int64) error {
	for {
		at, deadlineChanged, err := deadline.snapshot()
		if err != nil {
			return err
		}
		if !at.IsZero() && !at.After(time.Now()) {
			return os.ErrDeadlineExceeded
		}
		wakeAt := at
		if reset != 0 {
			resetAt := time.Unix(reset, 0)
			// An expired plan waits for publication rather than spinning on an
			// already elapsed midnight timer.
			if resetAt.After(time.Now()) && (wakeAt.IsZero() || resetAt.Before(wakeAt)) {
				wakeAt = resetAt
			}
		}
		var timer *time.Timer
		var timerC <-chan time.Time
		if !wakeAt.IsZero() {
			timer = time.NewTimer(time.Until(wakeAt))
			timerC = timer.C
		}
		select {
		case <-ready:
		case <-changed:
		case <-timerC:
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return ctx.Err()
		case <-deadlineChanged:
			if timer != nil {
				timer.Stop()
			}
			continue
		}
		if timer != nil {
			timer.Stop()
		}
		return nil
	}
}

// ReserveDatagram reserves quota before spending shared shaper credit. The
// caller commits the actual payload count after socket/reply-writer completion.
func (p Policy) ReserveDatagram(d Direction, size int, ticket *quota.Reservation) (bool, error) {
	if !p.admitIdentityPacket() {
		return false, ErrRateLimited
	}
	plan, err := p.QuotaPlan()
	if err != nil {
		return false, err
	}
	if plan != nil {
		if _, _, err := plan.TryReserve(time.Now(), quota.Direction(d), size, true, ticket); err != nil {
			if errors.Is(err, quota.ErrExhausted) {
				p.recordRejection(rejectQuota)
			} else {
				p.recordRejection(rejectQuotaCredit)
			}
			return false, err
		}
	}
	if !p.AllowDatagram(d, size) {
		p.recordRejection(rejectBandwidth)
		if plan != nil {
			ticket.Commit(0)
		}
		return false, ErrRateLimited
	}
	return plan != nil, nil
}
