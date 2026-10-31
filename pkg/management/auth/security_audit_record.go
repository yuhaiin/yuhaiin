package auth

import (
	"context"
	"database/sql"
	"encoding/json/v2"
	"strings"
	"time"
)

const auditColumns = `id,occurred_at,event,actor_id,subject_id,source,request_method,request_path,credential_id,result,changes_json,auth_method,policy_revision,reason`

func scanAuditEvent(row scanner) (SecurityEvent, error) {
	var e SecurityEvent
	err := row.Scan(&e.ID, &e.OccurredAt, &e.Event, &e.ActorID, &e.SubjectID, &e.Source, &e.Method, &e.Path, &e.CredentialID, &e.Result, &e.Changes, &e.AuthMethod, &e.PolicyRevision, &e.Reason)
	return e, err
}

// The caller commits the event and the management mutation in the same private
// transaction. Export failures never roll back a locally committed change.
func recordEvent(ctx context.Context, tx *sql.Tx, event, actor, subject string) (err error) {
	monitor, _ := ctx.Value(auditMonitorKey{}).(*Store)
	defer func() {
		if err != nil && monitor != nil {
			monitor.auditFailures.Add(1)
		}
	}()
	info, _ := ctx.Value(auditKey{}).(auditInfo)
	p, _ := FromContext(ctx)
	method := p.AuthMethod
	if p.CredentialType == "token" {
		method = "token"
	}
	if method == "" {
		si, _ := ctx.Value(sessionInfoKey{}).(sessionInfo)
		method = si.Method
	}
	if method == "" {
		method = "local"
	}
	result, reason := "succeeded", info.reason
	if strings.HasSuffix(event, ".failed") || strings.HasSuffix(event, ".denied") {
		result = "failed"
		if reason == "" {
			reason = event
		}
	}
	changes := info.changes
	if len(changes) > 16<<10 {
		encoded, _ := json.Marshal(struct {
			Truncated bool `json:"truncated"`
			Bytes     int  `json:"bytes"`
		}{true, len(changes)})
		changes = string(encoded)
	}
	now := time.Now().Unix()
	row, err := tx.ExecContext(ctx, `INSERT INTO management_security_events(occurred_at,event,actor_id,subject_id,source,request_method,request_path,credential_id,result,changes_json,auth_method,policy_revision,reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, now, event, actor, subject, info.source, info.method, info.path, p.CredentialID, result, changes, method, info.policyRevision, reason)
	if err != nil {
		return err
	}
	id, err := row.LastInsertId()
	if err != nil {
		return err
	}
	cfg, err := readAuditConfiguration(ctx, tx)
	if err != nil {
		return err
	}
	if err = pruneAudit(ctx, tx, cfg.AuditSettings, now); err != nil {
		return err
	}
	if cfg.ForwardEnabled {
		var count int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM management_audit_outbox`).Scan(&count); err != nil {
			return err
		}
		if count >= cfg.OutboxLimit {
			_, err = tx.ExecContext(ctx, `UPDATE management_audit_delivery SET dropped=dropped+1 WHERE id=1`)
		} else {
			payload, encodeErr := json.Marshal(auditRecord(SecurityEvent{ID: id, OccurredAt: now, Event: event, ActorID: actor, SubjectID: subject, Source: info.source, Method: info.method, Path: info.path, CredentialID: p.CredentialID, Result: result, Changes: changes, AuthMethod: method, PolicyRevision: info.policyRevision, Reason: reason}))
			if encodeErr != nil {
				return encodeErr
			}
			_, err = tx.ExecContext(ctx, `INSERT INTO management_audit_outbox(event_id,payload,created_at) VALUES(?,?,?)`, id, string(payload), now)
		}
		if err != nil {
			return err
		}
	}
	// The worker also polls after commit; an early wake cannot lose a record.
	if monitor != nil {
		if f := monitor.auditForwarder.Load(); f != nil {
			f.wake()
		}
	}
	return nil
}

func (s *Store) audit(ctx context.Context, event, actor, subject string) {
	ctx = context.WithValue(ctx, auditMonitorKey{}, s)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		s.auditFailures.Add(1)
		return
	}
	defer func() { _ = tx.Rollback() }()
	if recordEvent(ctx, tx, event, actor, subject) == nil {
		if tx.Commit() != nil {
			s.auditFailures.Add(1)
		}
	}
}
