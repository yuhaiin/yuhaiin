package auth

import (
	"context"
	"database/sql"
	"errors"

	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol/quota"
)

type quotaStore struct{ db *sql.DB }

func (s quotaStore) Load(ctx context.Context, key quota.Key) (quota.Record, error) {
	r := quota.Record{Key: key}
	var period string
	err := s.db.QueryRowContext(ctx, `SELECT period,owner_user_id FROM quota_definitions WHERE scope=? AND scope_id=? AND quota_id=?`, key.Scope, key.ScopeID, key.QuotaID).Scan(&period, &r.OwnerUserID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return r, err
	}
	if err == nil && period != key.Period {
		return r, errors.New("quota ID is already bound to a different period")
	}
	var low, high int64
	err = s.db.QueryRowContext(ctx, `SELECT measured_up,measured_down,measured_combined,charged_up,charged_down,charged_combined,alerts_low,alerts_high,denied FROM quota_windows WHERE scope=? AND scope_id=? AND quota_id=? AND period=? AND starts_at=?`, key.Scope, key.ScopeID, key.QuotaID, key.Period, key.StartsAt).Scan(
		&r.Measured[0], &r.Measured[1], &r.Measured[2], &r.Charged[0], &r.Charged[1], &r.Charged[2], &low, &high, &r.Denied)
	if errors.Is(err, sql.ErrNoRows) {
		return r, nil
	}
	r.Alerts = [2]uint64{uint64(low), uint64(high)}
	return r, err
}

func (s quotaStore) Save(ctx context.Context, records []quota.Record) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, r := range records {
		for i, n := range r.Charged {
			if n > 1<<63-1 || r.Measured[i] > n {
				return errors.New("invalid quota checkpoint")
			}
		}
		k := r.Key

		if k.Scope == "user" && r.OwnerUserID == "" {
			r.OwnerUserID = k.ScopeID
		}
		if k.Scope == "credential" && r.OwnerUserID == "" {
			return errors.New("credential quota has no owner")
		}
		result, err := tx.ExecContext(ctx, `INSERT INTO quota_definitions(scope,scope_id,quota_id,period,owner_user_id) VALUES(?,?,?,?,?) ON CONFLICT(scope,scope_id,quota_id) DO UPDATE SET owner_user_id=owner_user_id WHERE quota_definitions.owner_user_id=excluded.owner_user_id`, k.Scope, k.ScopeID, k.QuotaID, k.Period, r.OwnerUserID)
		if err != nil {
			return err
		}
		if n, err := result.RowsAffected(); err != nil || n != 1 {
			return errors.New("quota ownership changed")
		}

		// The composite foreign key rejects reusing an ID for another period.
		// Maximum counters and OR bits make ambiguous commit retries idempotent.
		_, err = tx.ExecContext(ctx, `INSERT INTO quota_windows(scope,scope_id,quota_id,period,starts_at,measured_up,measured_down,measured_combined,charged_up,charged_down,charged_combined,alerts_low,alerts_high,denied)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(scope,scope_id,quota_id,period,starts_at) DO UPDATE SET
		 measured_up=max(measured_up,excluded.measured_up), measured_down=max(measured_down,excluded.measured_down), measured_combined=max(measured_combined,excluded.measured_combined),
		 charged_up=max(charged_up,excluded.charged_up), charged_down=max(charged_down,excluded.charged_down), charged_combined=max(charged_combined,excluded.charged_combined),
		 alerts_low=alerts_low|excluded.alerts_low, alerts_high=alerts_high|excluded.alerts_high, denied=max(denied,excluded.denied)`,
			k.Scope, k.ScopeID, k.QuotaID, k.Period, k.StartsAt, r.Measured[0], r.Measured[1], r.Measured[2], r.Charged[0], r.Charged[1], r.Charged[2], int64(r.Alerts[0]), int64(r.Alerts[1]), r.Denied)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}
