package auth

import (
	"context"
	"strconv"

	"github.com/Asutorufa/yuhaiin/pkg/contract/resource"
)

const quotaAlertRetention = 10000

// One module worker owns this bounded batch. A failed batch remains queued;
// ledger overflow and persistence failures are independently observable.
func (r *ResourcePolicies) flushQuotaAlerts(ctx context.Context) (err error) {
	defer func() {
		r.alertBacklog.Store(int64(len(r.pendingAlerts)))
		if err != nil {
			r.alertFailures.Add(1)
		}
	}()
	for len(r.pendingAlerts) < 1024 {
		select {
		case event := <-r.Ledger.Events():
			r.pendingAlerts = append(r.pendingAlerts, event)
		default:
			goto save
		}
	}
save:
	if len(r.pendingAlerts) == 0 {
		return nil
	}
	tx, err := r.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, event := range r.pendingAlerts {
		k := event.Key
		if _, err := tx.ExecContext(ctx, `INSERT INTO quota_alerts(owner_user_id,scope,scope_id,quota_id,period,starts_at,occurred_at,threshold) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(scope,scope_id,quota_id,period,starts_at,threshold) DO NOTHING`, event.OwnerUserID, k.Scope, k.ScopeID, k.QuotaID, k.Period, k.StartsAt, event.At, event.Threshold); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM quota_alerts WHERE id<(SELECT id FROM quota_alerts ORDER BY id DESC LIMIT 1 OFFSET ?)`, quotaAlertRetention-1); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	clear(r.pendingAlerts)
	r.pendingAlerts = r.pendingAlerts[:0]
	return nil
}

func (r *ResourcePolicies) Alerts(ctx context.Context, owner, before string, limit int) (resource.AlertPage, error) {
	page := resource.AlertPage{Items: []resource.Alert{}, RetentionRows: quotaAlertRetention}
	if owner == "" {
		return page, nil
	}
	if len(owner) > 128 || len(before) > 19 || limit < 0 || limit > 200 {
		return page, ErrInvalid
	}
	if limit == 0 {
		limit = 50
	}
	var cursor int64 = 1<<63 - 1
	if before != "" {
		var err error
		cursor, err = strconv.ParseInt(before, 10, 64)
		if err != nil || cursor < 1 {
			return page, ErrInvalid
		}
	}
	rows, err := r.store.db.QueryContext(ctx, `SELECT id,occurred_at,scope,scope_id,quota_id,period,starts_at,threshold FROM quota_alerts
	 WHERE id<? AND ((scope IN ('user','credential') AND owner_user_id=?) OR (scope='group' AND scope_id IN (SELECT group_id FROM traffic_group_members WHERE user_id=?))) ORDER BY id DESC LIMIT ?`, cursor, owner, owner, limit)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var event resource.Alert
		if err := rows.Scan(&id, &event.OccurredAt, &event.Scope, &event.ScopeID, &event.QuotaID, &event.Period, &event.StartsAt, &event.Threshold); err != nil {
			return page, err
		}
		event.ID = strconv.FormatInt(id, 10)
		page.Items = append(page.Items, event)
	}
	if len(page.Items) == limit {
		page.Next = page.Items[len(page.Items)-1].ID
	}
	return page, rows.Err()
}
