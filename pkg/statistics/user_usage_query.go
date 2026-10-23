package statistics

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"slices"
	"strings"
	"time"

	usage "github.com/Asutorufa/yuhaiin/pkg/contract/usage"
)

var ErrUsageQuery = usage.ErrQuery

const usageSums = `COALESCE(SUM(upload_bytes),0),COALESCE(SUM(download_bytes),0),COALESCE(SUM(opened),0),
 COALESCE(SUM(failed),0),COALESCE(SUM(session_millis),0),COALESCE(MIN(NULLIF(first_seen,0)),0),COALESCE(MAX(last_seen),0)`

func usageWhere(q usage.Query) (string, []any) {
	var where strings.Builder
	where.WriteString(`user_id=?`)
	args := []any{q.UserID}
	for _, f := range []struct{ column, value string }{{"credential_id", q.CredentialID}, {"inbound_id", q.InboundID}, {"node_id", q.NodeID}, {"protocol", q.Protocol}} {
		if f.value != "" {
			where.WriteString(" AND " + f.column + "=?")
			args = append(args, f.value)
		}
	}
	return where.String(), args
}

func (r *UserUsage) normalizeQuery(q usage.Query) (usage.Query, error) {
	o := r.Options()
	if q.Interval == "" {
		q.Interval = "hour"
	}
	span := int64(3600)
	if q.Interval == "day" || q.Interval == "month" {
		span = 86400
	} else if q.Interval != "hour" {
		return q, ErrUsageQuery
	}
	now := time.Now().Unix()
	if q.To == 0 {
		q.To = now + 1
	}
	if q.From == 0 {
		q.From = now - 24*3600
	}
	if q.From < 0 || q.To <= q.From || q.To > now+span || q.To-q.From > int64(o.DailyDays)*86400 {
		return q, ErrUsageQuery
	}
	if q.Interval == "hour" && q.From < now-int64(o.HourlyDays)*86400 {
		return q, ErrUsageQuery
	}
	if q.From < now-int64(o.DailyDays)*86400 {
		return q, ErrUsageQuery
	}
	q.From = q.From / span * span
	q.To = (q.To + span - 1) / span * span
	return q, nil
}

type usageScanner interface{ Scan(...any) error }

func scanUsage(row usageScanner, leading ...any) (usage.Counters, error) {
	var a usageAmounts
	args := append(leading, &a.upload, &a.download, &a.opened, &a.failed, &a.millis, &a.first, &a.last)
	err := row.Scan(args...)
	return usage.Counters{Upload: formatUint64(a.upload), Download: formatUint64(a.download), Opened: formatUint64(a.opened), Failed: formatUint64(a.failed), SessionMillis: formatUint64(a.millis), FirstSeen: a.first, LastSeen: a.last}, err
}

func (r *UserUsage) Report(ctx context.Context, q usage.Query) (usage.Report, error) {
	q, err := r.normalizeQuery(q)
	if err != nil {
		return usage.Report{}, err
	}
	// Queries commit already sampled observations; they never scan payload or
	// force an additional per-packet clock/update on active connections.
	if err := r.Flush(ctx); err != nil {
		return usage.Report{}, err
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return usage.Report{}, err
	}
	defer func() { _ = tx.Rollback() }()
	where, args := usageWhere(q)
	lifetime, err := scanUsage(tx.QueryRowContext(ctx, `SELECT `+usageSums+` FROM user_usage_totals WHERE `+where, args...))
	if err != nil {
		return usage.Report{}, err
	}
	period := "hour"
	if q.Interval != "hour" {
		period = "day"
	}
	bucketWhere := where + ` AND period=? AND bucket>=? AND bucket<?`
	bucketArgs := append(append([]any{}, args...), period, q.From, q.To)
	counters, err := scanUsage(tx.QueryRowContext(ctx, `SELECT `+usageSums+` FROM user_usage_buckets WHERE `+bucketWhere, bucketArgs...))
	if err != nil {
		return usage.Report{}, err
	}
	report := usage.Report{Summary: usage.Summary{UserID: q.UserID, Lifetime: lifetime, Period: counters}, Interval: q.Interval, From: q.From, To: q.To, Series: []usage.Point{}}
	start := "bucket"
	if q.Interval == "month" {
		start = `CAST(strftime('%s',bucket,'unixepoch','start of month') AS INTEGER)`
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+start+`,`+usageSums+` FROM user_usage_buckets WHERE `+bucketWhere+` GROUP BY `+start+` ORDER BY `+start, bucketArgs...)
	if err != nil {
		return usage.Report{}, err
	}
	for rows.Next() {
		var p usage.Point
		p.Counters, err = scanUsage(rows, &p.Start)
		if err != nil {
			_ = rows.Close()
			return usage.Report{}, err
		}
		report.Series = append(report.Series, p)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return usage.Report{}, err
	}
	_ = rows.Close()
	for _, group := range []struct {
		column, name string
		out          *[]usage.Breakdown
	}{
		{"node_id", "node_name", &report.Nodes}, {"inbound_id", "inbound_name", &report.Inbounds}, {"credential_id", "credential_id", &report.Credentials}, {"protocol", "protocol", &report.Protocols},
	} {
		*group.out = []usage.Breakdown{}
		rows, err := tx.QueryContext(ctx, `SELECT `+group.column+`,MAX(`+group.name+`),`+usageSums+` FROM user_usage_buckets WHERE `+bucketWhere+` GROUP BY `+group.column+` ORDER BY SUM(upload_bytes)+SUM(download_bytes) DESC,`+group.column+` LIMIT 200`, bucketArgs...)
		if err != nil {
			return usage.Report{}, err
		}
		for rows.Next() {
			var b usage.Breakdown
			b.Counters, err = scanUsage(rows, &b.ID, &b.Name)
			if err != nil {
				_ = rows.Close()
				return usage.Report{}, err
			}
			*group.out = append(*group.out, b)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return usage.Report{}, err
		}
		_ = rows.Close()
	}
	var activeMinutes uint64
	err = tx.QueryRowContext(ctx, `SELECT active_minutes,peak_tcp,peak_udp FROM user_usage_users WHERE user_id=?`, q.UserID).Scan(&activeMinutes, &report.Summary.PeakTCP, &report.Summary.PeakUDP)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return usage.Report{}, err
	}
	report.Summary.ActiveMinutes = formatUint64(activeMinutes)
	var periodMinutes uint64
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_usage_activity WHERE user_id=? AND minute>=? AND minute<?`, q.UserID, q.From, q.To).Scan(&periodMinutes); err != nil {
		return usage.Report{}, err
	}
	report.Summary.PeriodActiveMinutes = formatUint64(periodMinutes)
	if err := tx.Commit(); err != nil {
		return usage.Report{}, err
	}
	r.mu.Lock()
	if l := r.live[q.UserID]; l != nil {
		report.Summary.ActiveTCP, report.Summary.ActiveUDP = l.tcp, l.udp
		report.Summary.PeakTCP = max(report.Summary.PeakTCP, l.peakTCP)
		report.Summary.PeakUDP = max(report.Summary.PeakUDP, l.peakUDP)
		report.Summary.UploadRate, report.Summary.DownloadRate = formatUint64(l.upload), formatUint64(l.download)
	} else {
		report.Summary.UploadRate, report.Summary.DownloadRate = "0", "0"
	}
	report.Health = r.healthLocked()
	report.UpdatedAt = r.lastSample.UnixMilli()
	r.mu.Unlock()
	return report, nil
}

type usageCursor struct {
	Time int64  `json:"time"`
	ID   string `json:"id"`
}

func (r *UserUsage) Audit(ctx context.Context, q usage.Query) (usage.AuditPage, error) {
	if q.Limit == 0 {
		q.Limit = 50
	}
	if q.Limit < 1 || q.Limit > 200 || q.From < 0 || q.To < 0 || (q.To != 0 && q.From >= q.To) {
		return usage.AuditPage{}, ErrUsageQuery
	}
	if len(q.Source) > 256 || len(q.Target) > 256 || len(q.Before) > 1024 {
		return usage.AuditPage{}, ErrUsageQuery
	}
	where, args := usageWhere(q)
	if q.From != 0 {
		where += ` AND started_at>=?`
		args = append(args, q.From*1000)
	}
	if q.To != 0 {
		where += ` AND started_at<?`
		args = append(args, q.To*1000)
	}
	if q.Result != "" {
		if !slices.Contains([]string{"active", "closed", "failed", "rejected", "interrupted"}, q.Result) {
			return usage.AuditPage{}, ErrUsageQuery
		}
		where += ` AND result=?`
		args = append(args, q.Result)
	}
	for _, f := range []struct{ column, value string }{{"source", q.Source}, {"target", q.Target}} {
		if f.value != "" {
			where += " AND " + f.column + "=?"
			args = append(args, f.value)
		}
	}
	if q.Before != "" {
		data, err := base64.RawURLEncoding.DecodeString(q.Before)
		if err != nil {
			return usage.AuditPage{}, ErrUsageQuery
		}
		var cursor usageCursor
		if json.Unmarshal(data, &cursor) != nil || cursor.Time < 0 || cursor.ID == "" {
			return usage.AuditPage{}, ErrUsageQuery
		}
		where += ` AND (started_at<? OR (started_at=? AND id<?))`
		args = append(args, cursor.Time, cursor.Time, cursor.ID)
	}
	if err := r.Flush(ctx); err != nil {
		return usage.AuditPage{}, err
	}
	args = append(args, q.Limit+1)
	rows, err := r.db.QueryContext(ctx, `SELECT data_json FROM user_usage_audit WHERE `+where+` ORDER BY started_at DESC,id DESC LIMIT ?`, args...)
	if err != nil {
		return usage.AuditPage{}, err
	}
	defer rows.Close()
	out := usage.AuditPage{Items: []usage.Audit{}}
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return out, err
		}
		var a usage.Audit
		if err := json.Unmarshal([]byte(data), &a); err != nil {
			return out, err
		}
		out.Items = append(out.Items, a)
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	if len(out.Items) > q.Limit {
		out.Items = out.Items[:q.Limit]
		a := out.Items[len(out.Items)-1]
		data, err := json.Marshal(usageCursor{a.StartedAt, a.ID})
		if err != nil {
			return out, err
		}
		out.Next = base64.RawURLEncoding.EncodeToString(data)
	}
	out.Health = r.Health()
	return out, nil
}

// UsageUsers lists stable historical IDs, including deleted users and the
// empty ID reserved for unattributed traffic. The caller enforces admin scope.
func (r *UserUsage) UsageUsers(ctx context.Context, after string, limit int) ([]string, error) {
	if limit < 1 || limit > 200 {
		return nil, ErrUsageQuery
	}
	rows, err := r.db.QueryContext(ctx, `SELECT DISTINCT user_id FROM user_usage_totals WHERE (?='' OR user_id>?) ORDER BY user_id LIMIT ?`, after, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
