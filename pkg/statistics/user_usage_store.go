package statistics

import (
	"context"
	"database/sql"
	"encoding/json/v2"
	"errors"
	"fmt"
	"time"

	usage "github.com/Asutorufa/yuhaiin/pkg/contract/usage"
)

const usageColumns = `user_id,credential_id,inbound_id,node_id,protocol,inbound_name,node_name,
 upload_bytes,download_bytes,opened,failed,session_millis,first_seen,last_seen`
const usageValues = `?,?,?,?,?,?,?,?,?,?,?,?,?,?`
const usageUpdate = `inbound_name=excluded.inbound_name,node_name=excluded.node_name,
 upload_bytes=upload_bytes+excluded.upload_bytes,download_bytes=download_bytes+excluded.download_bytes,
 opened=opened+excluded.opened,failed=failed+excluded.failed,session_millis=session_millis+excluded.session_millis,
 first_seen=CASE WHEN first_seen=0 THEN excluded.first_seen WHEN excluded.first_seen=0 THEN first_seen ELSE MIN(first_seen,excluded.first_seen) END,
 last_seen=MAX(last_seen,excluded.last_seen)`

func (r *UserUsage) recoverSessions(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx, `UPDATE user_usage_audit SET result='interrupted',
 data_json=json_set(data_json,'$.result','interrupted','$.reason','process_restarted','$.endedAt',checkpoint_at)
 WHERE result='active'`)
	return err
}

// Flush detaches an immutable batch. On failure it retries that same batch ID
// before newer observations. The transaction marker makes even an ambiguous
// commit retry idempotent; new traffic remains in a separate in-memory batch.
func (r *UserUsage) Flush(ctx context.Context) error {
	if r == nil {
		return nil
	}
	r.flushMu.Lock()
	defer r.flushMu.Unlock()
	if r.retry != nil {
		if err := r.persistUsage(ctx, r.retry); err != nil {
			r.setPersistenceError(true)
			return err
		}
		r.retry = nil
		r.mu.Lock()
		r.lastFlush = time.Now().UnixMilli()
		r.persistError = false
		r.mu.Unlock()
	}
	r.mu.Lock()
	if len(r.pending.groups) == 0 && len(r.pending.audit) == 0 && len(r.pending.activity) == 0 && len(r.pending.peaks) == 0 {
		r.persistError = false
		r.mu.Unlock()
		return nil
	}
	batch := r.pending
	r.pending = newUsageBatch()
	r.sequence++
	batch.id = fmt.Sprintf("%s:batch:%d", r.boot, r.sequence)
	r.mu.Unlock()
	if err := r.persistUsage(ctx, batch); err != nil {
		r.retry = batch
		r.setPersistenceError(true)
		return err
	}
	r.mu.Lock()
	r.lastFlush = time.Now().UnixMilli()
	r.persistError = false
	options := r.options
	r.mu.Unlock()
	if time.Since(r.lastMaintenance) >= time.Hour {
		if err := r.maintainUsage(ctx, options, time.Now()); err != nil {
			return err
		}
		r.lastMaintenance = time.Now()
	}
	return nil
}

func (r *UserUsage) setPersistenceError(failed bool) {
	r.mu.Lock()
	r.persistError = failed
	r.mu.Unlock()
}

func (r *UserUsage) persistUsage(ctx context.Context, batch *usageBatch) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var previous string
	err = tx.QueryRowContext(ctx, `SELECT batch_id FROM user_usage_flush WHERE id=1`).Scan(&previous)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if previous == batch.id {
		return nil
	}
	totals, err := tx.PrepareContext(ctx, `INSERT INTO user_usage_totals(`+usageColumns+`) VALUES(`+usageValues+`)
 ON CONFLICT(user_id,credential_id,inbound_id,node_id,protocol) DO UPDATE SET `+usageUpdate)
	if err != nil {
		return err
	}
	defer totals.Close()
	buckets, err := tx.PrepareContext(ctx, `INSERT INTO user_usage_buckets(period,bucket,`+usageColumns+`) VALUES(?,?,`+usageValues+`)
 ON CONFLICT(period,bucket,user_id,credential_id,inbound_id,node_id,protocol) DO UPDATE SET `+usageUpdate)
	if err != nil {
		return err
	}
	defer buckets.Close()
	for key, a := range batch.groups {
		args := []any{key.user, key.credential, key.inbound, key.node, key.protocol, a.inboundName, a.nodeName, a.upload, a.download, a.opened, a.failed, a.millis, a.first, a.last}
		if _, err := totals.ExecContext(ctx, args...); err != nil {
			return err
		}
		if _, err := buckets.ExecContext(ctx, append([]any{"hour", key.hour}, args...)...); err != nil {
			return err
		}
		if _, err := buckets.ExecContext(ctx, append([]any{"day", key.hour / 86400 * 86400}, args...)...); err != nil {
			return err
		}
	}
	activity, err := tx.PrepareContext(ctx, `INSERT OR IGNORE INTO user_usage_activity(user_id,minute) VALUES(?,?)`)
	if err != nil {
		return err
	}
	defer activity.Close()
	minutes, err := tx.PrepareContext(ctx, `INSERT INTO user_usage_users(user_id,active_minutes) VALUES(?,1)
 ON CONFLICT(user_id) DO UPDATE SET active_minutes=active_minutes+1`)
	if err != nil {
		return err
	}
	defer minutes.Close()
	for a := range batch.activity {
		result, err := activity.ExecContext(ctx, a.user, a.minute)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != 0 {
			if _, err := minutes.ExecContext(ctx, a.user); err != nil {
				return err
			}
		}
	}
	peaks, err := tx.PrepareContext(ctx, `INSERT INTO user_usage_users(user_id,peak_tcp,peak_udp) VALUES(?,?,?)
 ON CONFLICT(user_id) DO UPDATE SET peak_tcp=MAX(peak_tcp,excluded.peak_tcp),peak_udp=MAX(peak_udp,excluded.peak_udp)`)
	if err != nil {
		return err
	}
	defer peaks.Close()
	for user, p := range batch.peaks {
		if _, err := peaks.ExecContext(ctx, user, p[0], p[1]); err != nil {
			return err
		}
	}
	audit, err := tx.PrepareContext(ctx, `INSERT INTO user_usage_audit(id,user_id,credential_id,inbound_id,node_id,protocol,source,target,result,started_at,checkpoint_at,data_json)
 VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET result=excluded.result,checkpoint_at=excluded.checkpoint_at,data_json=excluded.data_json`)
	if err != nil {
		return err
	}
	defer audit.Close()
	now := time.Now().UnixMilli()
	completed := false
	for _, a := range batch.audit {
		completed = completed || a.Result != "active"
		data, err := json.Marshal(a)
		if err != nil {
			return err
		}
		checkpoint := now
		if a.EndedAt != 0 {
			checkpoint = a.EndedAt
		}
		if _, err := audit.ExecContext(ctx, a.ID, a.UserID, a.CredentialID, a.InboundID, a.NodeID, a.Protocol, a.Source, a.Target, a.Result, a.StartedAt, checkpoint, string(data)); err != nil {
			return err
		}
	}
	if completed {
		r.mu.Lock()
		limit := r.options.MaxAuditRows
		r.mu.Unlock()
		if _, err := tx.ExecContext(ctx, `DELETE FROM user_usage_audit WHERE id IN (SELECT id FROM user_usage_audit WHERE result!='active' ORDER BY started_at DESC,id DESC LIMIT -1 OFFSET ?)`, limit); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO user_usage_flush(id,batch_id) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET batch_id=excluded.batch_id`, batch.id); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *UserUsage) maintainUsage(ctx context.Context, o UsageOptions, now time.Time) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`DELETE FROM user_usage_buckets WHERE period='hour' AND bucket<?`, []any{now.AddDate(0, 0, -o.HourlyDays).UTC().Truncate(time.Hour).Unix()}},
		{`DELETE FROM user_usage_buckets WHERE period='day' AND bucket<?`, []any{now.AddDate(0, 0, -o.DailyDays).UTC().Truncate(24 * time.Hour).Unix()}},
		{`DELETE FROM user_usage_activity WHERE minute<?`, []any{now.AddDate(0, 0, -o.DailyDays).Unix()}},
		{`DELETE FROM user_usage_audit WHERE result!='active' AND checkpoint_at<?`, []any{now.AddDate(0, 0, -o.AuditDays).UnixMilli()}},
		{`DELETE FROM user_usage_audit WHERE id IN (SELECT id FROM user_usage_audit WHERE result!='active' ORDER BY started_at DESC,id DESC LIMIT -1 OFFSET ?)`, []any{o.MaxAuditRows}},
	} {
		if _, err := tx.ExecContext(ctx, q.sql, q.args...); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Options can be changed without resetting counters or disturbing connections.
func (r *UserUsage) Options() UsageOptions { r.mu.Lock(); defer r.mu.Unlock(); return r.options }

func (r *UserUsage) SetOptions(ctx context.Context, options UsageOptions) error {
	if validateUsageOptions(options) != nil {
		return ErrUsageQuery
	}
	data, err := json.Marshal(options)
	if err != nil {
		return err
	}
	r.flushMu.Lock()
	defer r.flushMu.Unlock()
	if _, err := r.db.ExecContext(ctx, `INSERT INTO user_usage_settings(id,options_json) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET options_json=excluded.options_json`, string(data)); err != nil {
		return err
	}
	r.mu.Lock()
	r.options = options
	r.mu.Unlock()
	if err := r.maintainUsage(ctx, options, time.Now()); err != nil {
		return err
	}
	r.lastMaintenance = time.Now()
	return nil
}

// Health is separate from use totals: audit overflow and persistence failures
// are observable and never silently presented as a complete audit trail.
func (r *UserUsage) Health() usage.Health { r.mu.Lock(); defer r.mu.Unlock(); return r.healthLocked() }
