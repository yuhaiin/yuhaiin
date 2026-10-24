package auth

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func benchmarkAuditStore(b *testing.B) *Store {
	b.Helper()
	db, err := storagesqlite.OpenManagement(b.Context(), filepath.Join(b.TempDir(), "management.db"))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = db.Close() })
	return NewStore(db.DB())
}

// This deliberately uses APIs present before phase 3, allowing the same fixture
// to measure baseline and current private-database transactions.
func seedAuditHistory(b *testing.B, s *Store) {
	b.Helper()
	if _, err := s.db.ExecContext(b.Context(), `WITH RECURSIVE ids(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM ids WHERE n<10000) INSERT INTO management_security_events(occurred_at,event,actor_id,subject_id) SELECT ?,'benchmark.updated','actor','resource' FROM ids`, time.Now().Unix()); err != nil {
		b.Fatal(err)
	}
}
func BenchmarkManagementAuditTransaction(b *testing.B) {
	s := benchmarkAuditStore(b)
	seedAuditHistory(b, s)
	ctx := b.Context()
	b.ReportAllocs()
	for b.Loop() {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			b.Fatal(err)
		}
		if err = recordEvent(ctx, tx, "benchmark.updated", "actor", "resource"); err != nil {
			_ = tx.Rollback()
			b.Fatal(err)
		}
		if err = tx.Commit(); err != nil {
			b.Fatal(err)
		}
	}
}
func BenchmarkManagementAuthenticate(b *testing.B) {
	s := benchmarkAuditStore(b)
	u, _, err := s.CreateUser(b.Context(), "local", "benchmark", Admin, false)
	if err != nil {
		b.Fatal(err)
	}
	if _, err = s.db.ExecContext(b.Context(), `UPDATE management_users SET credential='benchmark-only-record' WHERE id=?`, u.ID); err != nil {
		b.Fatal(err)
	}
	token, err := s.IssueToken(b.Context(), Principal{UserID: u.ID, Permissions: RolePermissions(Admin)}, u.ID, []Permission{NodesRead}, 0)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err = s.Authenticate(b.Context(), token.Secret, "token"); err != nil {
			b.Fatal(err)
		}
	}
}
func BenchmarkManagementAuditWithOutboxAndLocalAck(b *testing.B) {
	s := benchmarkAuditStore(b)
	seedAuditHistory(b, s)
	if _, err := s.db.ExecContext(b.Context(), `UPDATE management_audit_settings SET forward_enabled=1,forward_endpoint='https://siem.example'`); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		tx, err := s.db.BeginTx(b.Context(), nil)
		if err != nil {
			b.Fatal(err)
		}
		if err = recordEvent(context.WithValue(b.Context(), auditKey{}, auditInfo{changes: `{"before":{"revision":1},"after":{"revision":2}}`}), tx, "benchmark.updated", "actor", "resource"); err != nil {
			_ = tx.Rollback()
			b.Fatal(err)
		}
		if _, err = tx.ExecContext(b.Context(), `DELETE FROM management_audit_outbox`); err != nil {
			_ = tx.Rollback()
			b.Fatal(err)
		}
		if err = tx.Commit(); err != nil {
			b.Fatal(err)
		}
	}
}
