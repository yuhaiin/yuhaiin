package auth

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json/v2"
	"strconv"
	"strings"
)

type auditCursor struct {
	Instance string `json:"instance"`
	Upper    string `json:"upper"`
	Before   string `json:"before"`
}

// AuditPage pins an upper ID, not a long-running read transaction. Retention may
// expire older records between pages. IDs stay decimal strings for JS callers.
func (s *Store) AuditPage(ctx context.Context, q AuditQuery) (AuditPage, error) {
	out := AuditPage{Items: []AuditRecord{}}
	if q.Limit == 0 {
		q.Limit = 100
	}
	if q.Limit < 1 || q.Limit > 1000 || len(q.Cursor) > 512 || q.From < 0 || q.To < 0 || q.To > 0 && q.From > q.To {
		return out, ErrInvalid
	}
	for _, v := range []string{q.Event, q.ActorID, q.SubjectID, q.Result, q.AuthMethod, q.Reason, q.Search} {
		if len(v) > 256 {
			return out, ErrInvalid
		}
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return out, err
	}
	defer func() { _ = tx.Rollback() }()
	cfg, err := readAuditConfiguration(ctx, tx)
	if err != nil {
		return out, err
	}
	out.InstanceID = cfg.InstanceID
	var upper, before int64
	if q.Cursor == "" {
		if err = tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(id),0) FROM management_security_events`).Scan(&upper); err != nil {
			return out, err
		}
	} else {
		raw, decodeErr := base64.RawURLEncoding.DecodeString(q.Cursor)
		if decodeErr != nil {
			return out, ErrInvalid
		}
		var c auditCursor
		if json.Unmarshal(raw, &c) != nil || c.Instance != cfg.InstanceID {
			return out, ErrInvalid
		}
		upper, err = strconv.ParseInt(c.Upper, 10, 64)
		if err != nil || upper < 0 {
			return out, ErrInvalid
		}
		before, err = strconv.ParseInt(c.Before, 10, 64)
		if err != nil || before <= 0 || before > upper {
			return out, ErrInvalid
		}
	}
	where := []string{"id<=?"}
	args := []any{upper}
	if before > 0 {
		where = append(where, "id<?")
		args = append(args, before)
	}
	for _, f := range []struct{ col, val string }{{"event", q.Event}, {"actor_id", q.ActorID}, {"subject_id", q.SubjectID}, {"result", q.Result}, {"auth_method", q.AuthMethod}, {"reason", q.Reason}} {
		if f.val != "" {
			where = append(where, f.col+"=?")
			args = append(args, f.val)
		}
	}
	if q.From > 0 {
		where = append(where, "occurred_at>=?")
		args = append(args, q.From)
	}
	if q.To > 0 {
		where = append(where, "occurred_at<=?")
		args = append(args, q.To)
	}
	if q.Search != "" {
		pattern := "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(q.Search) + "%"
		where = append(where, `(event LIKE ? ESCAPE '\' OR actor_id LIKE ? ESCAPE '\' OR subject_id LIKE ? ESCAPE '\')`)
		args = append(args, pattern, pattern, pattern)
	}
	args = append(args, q.Limit+1)
	rows, err := tx.QueryContext(ctx, `SELECT `+auditColumns+` FROM management_security_events WHERE `+strings.Join(where, " AND ")+` ORDER BY id DESC LIMIT ?`, args...)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		e, err := scanAuditEvent(rows)
		if err != nil {
			return out, err
		}
		out.Items = append(out.Items, auditRecord(e))
	}
	if err = rows.Err(); err != nil {
		return out, err
	}
	if len(out.Items) > q.Limit {
		out.Items = out.Items[:q.Limit]
		raw, _ := json.Marshal(auditCursor{Instance: cfg.InstanceID, Upper: strconv.FormatInt(upper, 10), Before: out.Items[len(out.Items)-1].ID})
		out.NextCursor = base64.RawURLEncoding.EncodeToString(raw)
	}
	return out, nil
}

func (s *Store) AuditStatus(ctx context.Context) (AuditStatus, error) {
	out := AuditStatus{Running: s.auditForwarder.Load() != nil, LocalWriteFailures: strconv.FormatUint(s.auditFailures.Load(), 10)}
	err := s.db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM management_audit_outbox),(SELECT COALESCE(min(created_at),0) FROM management_audit_outbox),CAST(dropped AS TEXT),CAST(failures AS TEXT),CAST(delivered AS TEXT),last_success,last_failure,last_error FROM management_audit_delivery WHERE id=1`).Scan(&out.Backlog, &out.OldestQueuedAt, &out.Dropped, &out.DeliveryFailures, &out.Delivered, &out.LastSuccess, &out.LastFailure, &out.LastError)
	return out, err
}
