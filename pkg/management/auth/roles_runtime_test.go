package auth

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRoleRemovalCancelsActiveManagementRequest(t *testing.T) {
	s := testStore(t)
	admin := testUser(t, s, "admin", Admin)
	user := testUser(t, s, "auditor", NoManagement)
	a := principal(admin)
	role, err := s.SaveRole(t.Context(), a, Role{Name: "Auditor", Permissions: []Permission{SecurityRead}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AssignRoles(t.Context(), a, user.ID, 0, []string{role.ID}); err != nil {
		t.Fatal(err)
	}
	session := roleTestSession(t, s, user)
	entered, done := make(chan struct{}), make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v2/auth/events", func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
		w.WriteHeader(http.StatusNoContent)
	})
	server := &Server{Store: s, Permissions: map[string]Permission{"GET /api/v2/auth/events": SecurityRead}}
	r := httptest.NewRequest("GET", "/api/v2/auth/events", nil)
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("Authorization", "Session "+session.Secret)
	go func() { server.Wrap(mux).ServeHTTP(httptest.NewRecorder(), r); close(done) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("request did not enter")
	}
	if _, err := s.AssignRoles(t.Context(), a, user.ID, 1, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("request retained removed role permissions")
	}
}

func TestPasswordChangePreservesLastAdminUntilAtomicReplacement(t *testing.T) {
	s := testStore(t)
	admin := testUser(t, s, "admin", Admin)
	session := roleTestSession(t, s, admin)
	actor, err := s.Authenticate(t.Context(), session.Secret, "session")
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithPrincipal(t.Context(), actor)
	if _, err := s.ResetEnrollment(ctx, actor.UserID, actor.UserID); !errors.Is(err, ErrConflict) {
		t.Fatal("HTTP reset removed the last local administrator", err)
	}
	p, err := NewPasswordService(t.Context(), s)
	if err != nil {
		t.Fatal(err)
	}
	before, err := p.Parameters(t.Context(), admin.Login)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := s.StartPasswordChange(ctx, actor)
	if err != nil {
		t.Fatal(err)
	}
	after, err := p.Parameters(t.Context(), admin.Login)
	if err != nil || after.Salt != before.Salt {
		t.Fatal("abandoning a draft invalidates the current password", err)
	}
	if _, err := s.Authenticate(t.Context(), session.Secret, "session"); err != nil {
		t.Fatal("pending change revoked the last admin", err)
	}
	parameters, err := p.EnrollmentParameters(t.Context(), pending.Secret)
	if err != nil || parameters.Salt == before.Salt {
		t.Fatal("replacement did not use independent client salt", err)
	}
	credential := clientCredential(t, "replacement password", parameters)
	if err := p.Enroll(t.Context(), pending.Secret, credential); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(t.Context(), session.Secret, "session"); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("password replacement retained an old session", err)
	}
	if _, err := p.Login(t.Context(), admin.Login, credential); err != nil {
		t.Fatal("replacement admin cannot log in", err)
	}
	if err := p.Enroll(t.Context(), pending.Secret, credential); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("password-change capability replayed", err)
	}
}

func TestReadOnlyUserCanChangeOwnPasswordWithoutUsersManage(t *testing.T) {
	s := testStore(t)
	u := testUser(t, s, "reader", ReadOnly)
	session := roleTestSession(t, s, u)
	actor, err := s.Authenticate(t.Context(), session.Secret, "session")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartPasswordChange(WithPrincipal(t.Context(), actor), actor); err != nil {
		t.Fatal("own password change requires user administration", err)
	}
}
