package auth

import (
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	db, err := storagesqlite.OpenManagement(t.Context(), filepath.Join(t.TempDir(), "management.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return NewStore(db.DB())
}

// Store-only tests use a placeholder verifier. Password tests enroll real
// credentials through the independent Web Crypto client implementation.
func testUser(t *testing.T, s *Store, login, role string) User {
	t.Helper()
	u, _, err := s.CreateUser(t.Context(), "test", login, role, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(t.Context(), `UPDATE management_users SET credential='test-only-record' WHERE id=?`, u.ID); err != nil {
		t.Fatal(err)
	}
	u.Enrolled = true
	return u
}

func principal(u User) Principal {
	return Principal{UserID: u.ID, CredentialType: "session", Permissions: RolePermissions(u.Role)}
}

func TestTokenOwnerRoleIntersectionAndPromotion(t *testing.T) {
	s := testStore(t)
	admin := testUser(t, s, "admin", Admin)
	u := testUser(t, s, "reader", ReadOnly)
	token, err := s.IssueToken(t.Context(), principal(admin), u.ID, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	check := func(permission Permission, want bool) {
		t.Helper()
		p, err := s.Authenticate(t.Context(), token.Secret, "token")
		if err != nil || p.Allows(permission) != want {
			t.Fatalf("permission %s = %v, err %v, want %v", permission, p.Allows(permission), err, want)
		}
	}
	check(NodesRead, true)
	check(NodesWrite, false)
	if err := s.UpdateUser(t.Context(), admin.ID, u.ID, u.Login, Admin, false); err != nil {
		t.Fatal(err)
	}
	check(NodesWrite, false)
	full, err := s.IssueToken(t.Context(), principal(admin), u.ID, []Permission{NodesRead, NodesWrite}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateUser(t.Context(), admin.ID, u.ID, u.Login, ReadOnly, false); err != nil {
		t.Fatal(err)
	}
	p, err := s.Authenticate(t.Context(), full.Secret, "token")
	if err != nil || p.Allows(NodesWrite) || !p.Allows(NodesRead) {
		t.Fatalf("demotion permissions=%+v err=%v", p, err)
	}
	if _, err := s.IssueToken(t.Context(), Principal{UserID: u.ID, Permissions: []Permission{TokensOwn, NodesRead}}, u.ID, []Permission{NodesWrite}, 0); !errors.Is(err, ErrForbidden) {
		t.Fatalf("scope escalation: %v", err)
	}
}

func TestTokenVerifierRotationRevocationExpiryAndDisable(t *testing.T) {
	s := testStore(t)
	admin := testUser(t, s, "admin", Admin)
	u := testUser(t, s, "reader", ReadOnly)
	token, err := s.IssueToken(t.Context(), principal(u), u.ID, []Permission{NodesRead}, time.Now().Add(time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	var verifier []byte
	if err := s.db.QueryRowContext(t.Context(), `SELECT verifier FROM management_credentials WHERE id=?`, token.ID).Scan(&verifier); err != nil {
		t.Fatal(err)
	}
	expected := sha256.Sum256([]byte(token.Secret))
	if string(verifier) != string(expected[:]) || strings.Contains(string(verifier), token.Secret) {
		t.Fatal("database contains an incorrect verifier")
	}
	listed, err := s.Credentials(t.Context(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(listed)
	if strings.Contains(string(encoded), token.Secret) {
		t.Fatal("listing returned full token")
	}
	rotated, err := s.RotateToken(t.Context(), principal(u), token.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(t.Context(), token.Secret, "token"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("old token survived rotation: %v", err)
	}
	if err := s.Revoke(t.Context(), principal(u), rotated.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(t.Context(), rotated.Secret, "token"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked token: %v", err)
	}
	token, err = s.IssueToken(t.Context(), principal(u), u.ID, []Permission{NodesRead}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(t.Context(), `UPDATE management_credentials SET expires_at=? WHERE id=?`, time.Now().Add(-time.Second).Unix(), token.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(t.Context(), token.Secret, "token"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expired token: %v", err)
	}
	token, err = s.IssueToken(t.Context(), principal(u), u.ID, []Permission{NodesRead}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateUser(t.Context(), admin.ID, u.ID, u.Login, u.Role, true); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateUser(t.Context(), admin.ID, u.ID, u.Login, u.Role, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(t.Context(), token.Secret, "token"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("reenable resurrected token: %v", err)
	}
}

func TestLastAdministratorAndPendingAccounts(t *testing.T) {
	s := testStore(t)
	admin := testUser(t, s, "admin", Admin)
	_, _, err := s.CreateUser(t.Context(), admin.ID, "pending", Admin, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []func() error{
		func() error { return s.DeleteUser(t.Context(), admin.ID, admin.ID) },
		func() error { return s.UpdateUser(t.Context(), admin.ID, admin.ID, admin.Login, ReadOnly, false) },
		func() error { return s.UpdateUser(t.Context(), admin.ID, admin.ID, admin.Login, Admin, true) },
	} {
		if err := operation(); !errors.Is(err, ErrConflict) {
			t.Fatalf("last admin protection: %v", err)
		}
	}
	second := testUser(t, s, "second", Admin)
	if err := s.DeleteUser(t.Context(), second.ID, admin.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.CreateUser(t.Context(), "local", "new", Admin, true); !errors.Is(err, ErrConflict) {
		t.Fatalf("rebootstrap: %v", err)
	}
	if _, _, err := s.CreateUser(t.Context(), second.ID, "SECOND", ReadOnly, false); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate login: %v", err)
	}
}

func TestResetInvalidatesAllCredentialKindsAndBoundsAudit(t *testing.T) {
	s := testStore(t)
	u := testUser(t, s, "admin", Admin)
	token, err := s.IssueToken(t.Context(), principal(u), u.ID, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := s.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	session, err := issueCredential(t.Context(), tx, u.ID, "session", nil, time.Now().Add(time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResetEnrollment(t.Context(), "local", u.ID); err != nil {
		t.Fatal(err)
	}
	for _, cred := range []IssuedCredential{token, session} {
		if _, err := s.Authenticate(t.Context(), cred.Secret, cred.Kind); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("reset did not revoke %s: %v", cred.Kind, err)
		}
	}
	u, err = s.User(t.Context(), u.ID)
	if err != nil || u.Enrolled {
		t.Fatalf("old password record survived reset: %+v, %v", u, err)
	}
	tx, err = s.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for range 1010 {
		if err := recordEvent(context.Background(), tx, "login.failed", "", ""); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	events, err := s.Events(t.Context())
	if err != nil || len(events) != 1000 {
		t.Fatalf("audit size=%d, err=%v", len(events), err)
	}
}
