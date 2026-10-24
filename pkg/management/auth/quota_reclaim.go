package auth

import (
	"context"
	"errors"

	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol/quota"
)

func (s quotaStore) Reclaim(ctx context.Context, requests []quota.Reclaim) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, request := range requests {
		r, k := request.Record, request.Record.Key
		for i, n := range r.Charged {
			if n < r.Measured[i] || request.MaxCharged[i] < n || request.MaxCharged[i] > 1<<63-1 {
				return errors.New("invalid quota credit reclaim")
			}
		}
		result, err := tx.ExecContext(ctx, `UPDATE quota_windows SET
		 measured_up=max(measured_up,?),measured_down=max(measured_down,?),measured_combined=max(measured_combined,?),
		 charged_up=?,charged_down=?,charged_combined=?,alerts_low=alerts_low|?,alerts_high=alerts_high|?,denied=max(denied,?)
		 WHERE scope=? AND scope_id=? AND quota_id=? AND period=? AND starts_at=?
		 AND charged_up BETWEEN ? AND ? AND charged_down BETWEEN ? AND ? AND charged_combined BETWEEN ? AND ?`,
			r.Measured[0], r.Measured[1], r.Measured[2], r.Charged[0], r.Charged[1], r.Charged[2], int64(r.Alerts[0]), int64(r.Alerts[1]), r.Denied,
			k.Scope, k.ScopeID, k.QuotaID, k.Period, k.StartsAt, r.Charged[0], request.MaxCharged[0], r.Charged[1], request.MaxCharged[1], r.Charged[2], request.MaxCharged[2])
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			if r.Charged == (quota.Amounts{}) && r.Measured == (quota.Amounts{}) {
				var exists int
				if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM quota_windows WHERE scope=? AND scope_id=? AND quota_id=? AND period=? AND starts_at=?`, k.Scope, k.ScopeID, k.QuotaID, k.Period, k.StartsAt).Scan(&exists); err != nil {
					return err
				}
				if exists == 0 {
					continue
				}
			}
			return errors.New("quota credit changed during reclaim")
		}
	}
	return tx.Commit()
}
