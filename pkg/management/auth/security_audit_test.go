package auth

import (
	"context"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func enableTestAudit(t *testing.T, s *Store, limit int) AuditSettings {
	t.Helper()
	_, err := s.db.ExecContext(t.Context(), `UPDATE management_audit_settings SET forward_enabled=1,forward_endpoint='https://siem.example/events',outbox_limit=? WHERE id=1`, limit)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := s.AuditSettings(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}
func appendTestAudit(t *testing.T, s *Store, event, subject string) {
	t.Helper()
	ctx := WithPrincipal(context.WithValue(t.Context(), auditMonitorKey{}, s), Principal{UserID: "actor", CredentialID: "credential", CredentialType: "token", AuthMethod: "password"})
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if err = recordEvent(ctx, tx, event, "actor", subject); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
}
func TestAuditCursorExactIDsFiltersAndPinnedUpper(t *testing.T) {
	s := testStore(t)
	if _, err := s.db.ExecContext(t.Context(), `UPDATE management_audit_settings SET max_age_days=0`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(t.Context(), `INSERT INTO management_security_events(id,occurred_at,event,actor_id,subject_id) VALUES(9007199254740993,100,'policy.updated','a','100%_resource'),(9007199254740995,200,'policy.updated','b','ordinary'),(9007199254740998,300,'policy.denied','a','100%_resource')`); err != nil {
		t.Fatal(err)
	}
	page, err := s.AuditPage(t.Context(), AuditQuery{Limit: 1})
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != "9007199254740998" || page.NextCursor == "" {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	appendTestAudit(t, s, "new.updated", "new")
	next, err := s.AuditPage(t.Context(), AuditQuery{Cursor: page.NextCursor, Limit: 1})
	if err != nil || len(next.Items) != 1 || next.Items[0].ID != "9007199254740995" {
		t.Fatalf("next=%+v err=%v", next, err)
	}
	filtered, err := s.AuditPage(t.Context(), AuditQuery{ActorID: "a", Search: "%_", From: 100, To: 250, Event: "policy.updated"})
	if err != nil || len(filtered.Items) != 1 || filtered.Items[0].ID != "9007199254740993" {
		t.Fatalf("filter=%+v err=%v", filtered, err)
	}
	for _, q := range []AuditQuery{{Limit: 1001}, {From: -1}, {From: 3, To: 2}, {Cursor: "invalid"}, {Search: strings.Repeat("x", 257)}} {
		if _, err := s.AuditPage(t.Context(), q); !errors.Is(err, ErrInvalid) {
			t.Fatalf("accepted %+v: %v", q, err)
		}
	}
	if _, err := s.db.ExecContext(t.Context(), `UPDATE management_audit_settings SET instance_id='other'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AuditPage(t.Context(), AuditQuery{Cursor: page.NextCursor}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("cross-instance cursor: %v", err)
	}
}
func TestAuditQueueOverflowRetentionAndMetadata(t *testing.T) {
	s := testStore(t)
	enableTestAudit(t, s, 64)
	for i := range 66 {
		appendTestAudit(t, s, "permission.denied", strconv.Itoa(i))
	}
	status, err := s.AuditStatus(t.Context())
	if err != nil || status.Backlog != 64 || status.Dropped != "2" {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	events, err := s.Events(t.Context())
	if err != nil || len(events) != 66 || events[0].AuthMethod != "token" || events[0].Reason != "permission.denied" || events[0].CredentialID != "credential" {
		t.Fatalf("events=%+v err=%v", events, err)
	}
	if _, err := s.db.ExecContext(t.Context(), `UPDATE management_security_events SET occurred_at=1; UPDATE management_audit_outbox SET created_at=1`); err != nil {
		t.Fatal(err)
	}
	appendTestAudit(t, s, "local.updated", "new")
	status, err = s.AuditStatus(t.Context())
	if err != nil || status.Backlog != 1 || status.Dropped != "66" {
		t.Fatalf("expired=%+v err=%v", status, err)
	}
	events, err = s.Events(t.Context())
	if err != nil || len(events) != 1 {
		t.Fatalf("retained=%d err=%v", len(events), err)
	}
	// Count retention counts actual rows even when IDs have large gaps.
	if _, err = s.db.ExecContext(t.Context(), `UPDATE management_audit_settings SET max_events=1000,forward_enabled=0`); err != nil {
		t.Fatal(err)
	}
	tx, err := s.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 1010 {
		if _, err = tx.ExecContext(t.Context(), `INSERT INTO management_security_events(id,occurred_at,event,actor_id,subject_id) VALUES(?,?,?,?,?)`, int64(10000+i*3), time.Now().Unix(), "gap.updated", "a", ""); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := readAuditConfiguration(t.Context(), tx)
	if err != nil {
		t.Fatal(err)
	}
	if err = pruneAudit(t.Context(), tx, cfg.AuditSettings, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = s.db.QueryRowContext(t.Context(), `SELECT count(*) FROM management_security_events`).Scan(&count); err != nil || count != 1000 {
		t.Fatalf("count=%d err=%v", count, err)
	}
}
func TestAuditSettingsScopesConflictSecretAndFailureRollback(t *testing.T) {
	s := testStore(t)
	admin := testUser(t, s, "admin", Admin)
	p := principal(admin)
	cfg, err := s.AuditSettings(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	cfg.Endpoint = "https://siem.example/private-webhook-proof"
	cfg.ForwardEnabled = true
	saved, err := s.SaveAuditSettings(WithPrincipal(t.Context(), p), p, AuditSettingsRequest{AuditSettings: cfg, Token: "private-siem-token"})
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(saved)
	events, _ := s.Events(t.Context())
	auditJSON, _ := json.Marshal(events)
	if !saved.TokenConfigured || (strings.Contains(string(encoded)+string(auditJSON), "private-siem-token") || strings.Contains(string(encoded)+string(auditJSON), "private-webhook-proof")) {
		t.Fatal("secret exposed in settings or ledger")
	}
	limited := p
	limited.Permissions = []Permission{SecurityWrite}
	if _, err = s.SaveAuditSettings(WithPrincipal(t.Context(), limited), limited, AuditSettingsRequest{AuditSettings: saved, Token: "private-siem-token"}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("equal secret oracle: %v", err)
	}
	if _, err = s.SaveAuditSettings(t.Context(), p, AuditSettingsRequest{AuditSettings: cfg}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale revision: %v", err)
	}
	if _, err = s.db.ExecContext(t.Context(), `CREATE TRIGGER audit_break BEFORE INSERT ON management_security_events BEGIN SELECT RAISE(FAIL,'test audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	changed := saved
	changed.MaxAgeDays = 30
	if _, err = s.SaveAuditSettings(WithPrincipal(t.Context(), p), p, AuditSettingsRequest{AuditSettings: changed}); err == nil {
		t.Fatal("change succeeded without durable audit")
	}
	current, _ := s.AuditSettings(t.Context())
	if current.Revision != saved.Revision || current.MaxAgeDays != saved.MaxAgeDays {
		t.Fatal("unaudited settings committed")
	}
	if _, err = s.auditExport(WithPrincipal(t.Context(), p), p, AuditQuery{}); err == nil {
		t.Fatal("export succeeded without durable authorization")
	}
	if _, err = s.auditExport(t.Context(), limited, AuditQuery{}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("export scope: %v", err)
	}
}

type auditSenderFunc func(context.Context, auditConfiguration, []AuditRecord) error

func (f auditSenderFunc) send(ctx context.Context, cfg auditConfiguration, r []AuditRecord) error {
	return f(ctx, cfg, r)
}
func TestAuditForwarderRetriesRestartAndRevisionAck(t *testing.T) {
	s := testStore(t)
	enableTestAudit(t, s, 64)
	appendTestAudit(t, s, "policy.updated", "policy")
	sender := auditSenderFunc(func(context.Context, auditConfiguration, []AuditRecord) error {
		return auditDeliveryError("delivery_http_rejected")
	})
	f := &AuditForwarder{store: s, sender: sender}
	if _, err := f.drain(t.Context()); err == nil {
		t.Fatal("delivery failure not reported")
	}
	status, _ := s.AuditStatus(t.Context())
	if status.Backlog != 1 || status.DeliveryFailures != "1" || status.LastError != "delivery_http_rejected" {
		t.Fatalf("failure %+v", status)
	}
	// Simulate a restarted worker on the same durable outbox.
	f = &AuditForwarder{store: s, sender: auditSenderFunc(func(ctx context.Context, _ auditConfiguration, records []AuditRecord) error {
		if len(records) != 1 || records[0].SubjectID != "policy" {
			t.Fatalf("records=%+v", records)
		}
		_, err := s.db.ExecContext(ctx, `UPDATE management_audit_settings SET revision=revision+1`)
		return err
	})}
	if _, err := f.drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	status, _ = s.AuditStatus(t.Context())
	if status.Backlog != 1 || status.Delivered != "0" {
		t.Fatalf("stale target ACK %+v", status)
	}
	f.sender = auditSenderFunc(func(context.Context, auditConfiguration, []AuditRecord) error { return nil })
	if _, err := f.drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	status, _ = s.AuditStatus(t.Context())
	if status.Backlog != 0 || status.Delivered != "1" || status.LastError != "" {
		t.Fatalf("ack %+v", status)
	}
}
func TestAuditForwarderCancellationAndSingleton(t *testing.T) {
	s := testStore(t)
	enableTestAudit(t, s, 64)
	appendTestAudit(t, s, "policy.updated", "policy")
	started := make(chan struct{}, 1)
	cancelled := make(chan struct{}, 1)
	var calls atomic.Int32
	f, err := newAuditForwarder(t.Context(), s, auditSenderFunc(func(ctx context.Context, _ auditConfiguration, _ []AuditRecord) error {
		calls.Add(1)
		select {
		case started <- struct{}{}:
		default:
		}
		<-ctx.Done()
		select {
		case cancelled <- struct{}{}:
		default:
		}
		return ctx.Err()
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = newAuditForwarder(t.Context(), s, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate worker %v", err)
	}
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not start")
	}
	f.changed()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("inflight target not cancelled")
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	status, _ := s.AuditStatus(t.Context())
	if status.Running || status.Backlog != 1 {
		t.Fatalf("closed %+v", status)
	}
}
func TestAuditOutboxFailureRollsBackRoleChange(t *testing.T) {
	s := testStore(t)
	admin := testUser(t, s, "admin", Admin)
	enableTestAudit(t, s, 64)
	if _, err := s.db.ExecContext(t.Context(), `CREATE TRIGGER outbox_break BEFORE INSERT ON management_audit_outbox BEGIN SELECT RAISE(FAIL,'test outbox failure'); END`); err != nil {
		t.Fatal(err)
	}
	p := principal(admin)
	ctx := WithPrincipal(context.WithValue(t.Context(), auditMonitorKey{}, s), p)
	if _, err := s.SaveRole(ctx, p, Role{Name: "unaudited", Permissions: []Permission{NodesRead}}); err == nil {
		t.Fatal("role persisted without audit outbox")
	}
	var count int
	if err := s.db.QueryRowContext(t.Context(), `SELECT count(*) FROM management_roles`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("role count=%d err=%v", count, err)
	}
	status, _ := s.AuditStatus(t.Context())
	if status.LocalWriteFailures != "1" {
		t.Fatalf("failure counter %+v", status)
	}
}
func TestAuditHTTPExportPermissionAndQuery(t *testing.T) {
	s := testStore(t)
	admin := testUser(t, s, "admin", Admin)
	p := principal(admin)
	full, err := s.IssueToken(t.Context(), p, admin.ID, []Permission{SecurityRead, SecurityExport}, 0)
	if err != nil {
		t.Fatal(err)
	}
	read, err := s.IssueToken(t.Context(), p, admin.ID, []Permission{SecurityRead}, 0)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	server := &Server{Store: s}
	server.Register(mux)
	handler := server.Wrap(mux)
	for _, tc := range []struct {
		path, token string
		code        int
	}{{"/events/page?limit=1", read.Secret, 200}, {"/events/export", read.Secret, 403}, {"/events/export?limit=1", full.Secret, 200}, {"/events/page?from=no", full.Secret, 400}, {"/events/status", read.Secret, 200}} {
		req := httptest.NewRequest(http.MethodGet, "http://localhost/api/v2/auth"+tc.path, nil)
		req.RemoteAddr = "127.0.0.1:1234"
		req.Header.Set("Authorization", "Bearer "+tc.token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != tc.code {
			t.Fatalf("%s status=%d body=%s", tc.path, w.Code, w.Body.String())
		}
		if tc.code == 200 && strings.Contains(tc.path, "export") && !strings.Contains(w.Header().Get("Content-Disposition"), "attachment") {
			t.Fatal("missing download header")
		}
	}
}
func TestAuditLargeDiffIsBoundedAndRevisionCaptured(t *testing.T) {
	s := testStore(t)
	ctx, err := roleAuditContext(t.Context(), nil, struct {
		Revision uint64 `json:"revision"`
		Name     string `json:"name"`
	}{42, strings.Repeat("x", 20000)})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = recordEvent(ctx, tx, "policy.updated", "actor", "policy"); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	page, err := s.AuditPage(t.Context(), AuditQuery{})
	if err != nil || len(page.Items) != 1 || page.Items[0].PolicyRevision != "42" || len(page.Items[0].Changes) > 100 || !strings.Contains(page.Items[0].Changes, `"truncated":true`) {
		t.Fatalf("page=%+v err=%v", page, err)
	}
}
func TestAuditEndpointValidation(t *testing.T) {
	base := AuditSettings{Revision: 1, MaxEvents: 1000, OutboxLimit: 64, Transport: "https", ForwardEnabled: true}
	for _, endpoint := range []string{"http://siem.example", "https://user:secret@siem.example", "https://siem.example?token=secret", "https://siem.example#secret", "https://siem.example?"} {
		cfg := base
		cfg.Endpoint = endpoint
		if validAuditSettings(cfg) {
			t.Fatalf("unsafe endpoint %s", endpoint)
		}
	}
}

func TestAuditSessionAuthenticationMethodComesFromCredential(t *testing.T) {
	s := testStore(t)
	u := testUser(t, s, "sso-user", ReadOnly)
	tx, err := s.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	issued, err := issueCredential(t.Context(), tx, u.ID, "session", nil, time.Now().Add(time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	if err = saveSessionInfo(t.Context(), tx, issued.ID, sessionInfo{Method: "oidc-enterprise"}); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	p, err := s.Authenticate(t.Context(), issued.Secret, "session")
	if err != nil || p.AuthMethod != "oidc-enterprise" {
		t.Fatalf("principal=%+v err=%v", p, err)
	}
	s.audit(WithPrincipal(t.Context(), p), "session.inspected", u.ID, "sessions")
	page, err := s.AuditPage(t.Context(), AuditQuery{Event: "session.inspected"})
	if err != nil || len(page.Items) != 1 || page.Items[0].AuthMethod != "oidc-enterprise" {
		t.Fatalf("audit=%+v err=%v", page, err)
	}
}
