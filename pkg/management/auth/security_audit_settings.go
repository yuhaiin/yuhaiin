package auth

import (
	"context"
	"database/sql"
	"github.com/Asutorufa/yuhaiin/pkg/security/configchange"
	"net/url"
	"strings"
	"time"
)

type auditRowReader interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func readAuditConfiguration(ctx context.Context, q auditRowReader) (auditConfiguration, error) {
	var out auditConfiguration
	err := q.QueryRowContext(ctx, `SELECT instance_id,revision,max_events,max_age_days,forward_enabled,forward_transport,forward_endpoint,forward_token,outbox_limit FROM management_audit_settings WHERE id=1`).Scan(&out.InstanceID, &out.Revision, &out.MaxEvents, &out.MaxAgeDays, &out.ForwardEnabled, &out.Transport, &out.Endpoint, &out.token, &out.OutboxLimit)
	out.TokenConfigured = out.token != ""
	out.EndpointConfigured = out.Endpoint != ""
	if target, parseErr := url.Parse(out.Endpoint); parseErr == nil && out.Endpoint != "" {
		out.Destination = target.Scheme + "://" + target.Host
	}
	return out, err
}
func (s *Store) AuditSettings(ctx context.Context) (AuditSettings, error) {
	cfg, err := readAuditConfiguration(ctx, s.db)
	return publicAuditSettings(cfg), err
}

// Forwarding URLs can contain reusable webhook proofs in their path. Only
// the origin is public; blank writes preserve the private destination.
func publicAuditSettings(cfg auditConfiguration) AuditSettings {
	out := cfg.AuditSettings
	out.Endpoint = ""
	return out
}
func validAuditSettings(cfg AuditSettings) bool {
	if cfg.MaxEvents < 1000 || cfg.MaxEvents > 100000 || cfg.MaxAgeDays < 0 || cfg.MaxAgeDays > 3650 || cfg.OutboxLimit < 64 || cfg.OutboxLimit > 16384 || cfg.Revision == 0 || cfg.Revision > (1<<53)-1 || len(cfg.Endpoint) > 2048 {
		return false
	}
	if cfg.Transport != "https" && cfg.Transport != "syslog-tls" {
		return false
	}
	if cfg.Endpoint == "" {
		return !cfg.ForwardEnabled
	}
	endpoint, err := url.Parse(cfg.Endpoint)
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" {
		return false
	}
	if cfg.Transport == "https" {
		return endpoint.Scheme == "https"
	}
	return endpoint.Scheme == "tls" && (endpoint.Path == "" || endpoint.Path == "/")
}
func (s *Store) SaveAuditSettings(ctx context.Context, actor Principal, request AuditSettingsRequest) (AuditSettings, error) {
	if len(request.Token) > 4096 || strings.ContainsAny(request.Token, "\r\n") {
		return AuditSettings{}, ErrInvalid
	}
	tx, err := configchange.Begin(ctx, s.db, "audit-settings")
	if err != nil {
		return AuditSettings{}, err
	}
	defer func() { _ = tx.Rollback() }()
	actor, err = freshRoleActor(ctx, tx, actor)
	if err != nil || !actor.Allows(SecurityWrite) || (request.Token != "" || request.ClearToken || request.Endpoint != "" || request.ClearEndpoint) && !actor.Allows(SecretsManage) {
		return AuditSettings{}, ErrForbidden
	}
	before, err := readAuditConfiguration(ctx, tx)
	if err != nil {
		return AuditSettings{}, err
	}
	if request.Revision != before.Revision || before.Revision >= (1<<53)-1 {
		return AuditSettings{}, ErrConflict
	}
	var queued int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM management_audit_outbox`).Scan(&queued); err != nil {
		return AuditSettings{}, err
	}
	if request.OutboxLimit < queued {
		return AuditSettings{}, ErrConflict
	}
	token := before.token
	if request.ClearToken {
		token = ""
	} else if request.Token != "" {
		token = request.Token
	}
	after := request.AuditSettings
	after.InstanceID = before.InstanceID
	after.Revision++
	after.TokenConfigured = token != ""
	after.Endpoint = before.Endpoint
	if request.ClearEndpoint {
		after.Endpoint = ""
	} else if request.Endpoint != "" {
		after.Endpoint = request.Endpoint
	}
	after.EndpointConfigured = after.Endpoint != ""
	after.Destination = ""
	if target, parseErr := url.Parse(after.Endpoint); parseErr == nil && after.Endpoint != "" {
		after.Destination = target.Scheme + "://" + target.Host
	}
	if !validAuditSettings(after) {
		return AuditSettings{}, ErrInvalid
	}
	if after.Transport == "syslog-tls" && token != "" {
		return AuditSettings{}, ErrInvalid
	}
	if _, err := tx.ExecContext(ctx, `UPDATE management_audit_settings SET revision=?,max_events=?,max_age_days=?,forward_enabled=?,forward_transport=?,forward_endpoint=?,forward_token=?,outbox_limit=? WHERE id=1`, after.Revision, after.MaxEvents, after.MaxAgeDays, after.ForwardEnabled, after.Transport, after.Endpoint, token, after.OutboxLimit); err != nil {
		return AuditSettings{}, err
	}
	publicAfter := publicAuditSettings(auditConfiguration{AuditSettings: after})
	afterMetadata := struct {
		AuditSettings
		EndpointChanged bool `json:"endpointChanged"`
		TokenChanged    bool `json:"tokenChanged"`
	}{AuditSettings: publicAfter, EndpointChanged: before.Endpoint != after.Endpoint, TokenChanged: before.token != token}
	ctx, err = roleAuditContext(ctx, publicAuditSettings(before), afterMetadata)
	if err != nil {
		return AuditSettings{}, err
	}
	if err := recordEvent(ctx, tx, "security.audit_settings_updated", actor.UserID, "management-audit"); err != nil {
		return AuditSettings{}, err
	}
	privateBefore := AuditSettingsRequest{AuditSettings: before.AuditSettings, Token: before.token}
	privateAfter := AuditSettingsRequest{AuditSettings: after, Token: token}
	if err := configchange.RecordValues(ctx, s.db, tx, "audit-settings", "management-audit", after.Revision, privateBefore, privateAfter, publicAuditSettings(before), afterMetadata); err != nil {
		return AuditSettings{}, err
	}
	if err := configchange.Commit(ctx, tx); err != nil {
		return AuditSettings{}, err
	}
	if forwarder := s.auditForwarder.Load(); forwarder != nil {
		forwarder.changed()
	}
	return publicAfter, nil
}
func pruneAudit(ctx context.Context, tx *sql.Tx, cfg AuditSettings, now int64) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM management_security_events WHERE id IN (SELECT id FROM management_security_events ORDER BY id LIMIT (SELECT max(0,retained_events-?) FROM management_audit_settings WHERE id=1))`, cfg.MaxEvents); err != nil {
		return err
	}
	if cfg.MaxAgeDays == 0 {
		return nil
	}
	cutoff := now - int64(cfg.MaxAgeDays)*int64((24*time.Hour)/time.Second)
	if _, err := tx.ExecContext(ctx, `DELETE FROM management_security_events WHERE occurred_at<?`, cutoff); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM management_audit_outbox WHERE created_at<?`, cutoff)
	if err != nil {
		return err
	}
	dropped, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if dropped > 0 {
		_, err = tx.ExecContext(ctx, `UPDATE management_audit_delivery SET dropped=dropped+? WHERE id=1`, dropped)
	}
	return err
}
