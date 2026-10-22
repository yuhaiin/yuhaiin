package auth

import (
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSessionsOwnershipFilteringAndRevocation(t *testing.T) {
	s := testStore(t)
	admin := testUser(t, s, "admin", Admin)
	user := testUser(t, s, "reader", ReadOnly)
	current := testSession(t, s, user)
	second := testSession(t, s, user)
	expired := testSession(t, s, user)
	other := testSession(t, s, admin)
	if _, err := s.db.ExecContext(t.Context(), `UPDATE management_credentials SET expires_at=? WHERE id=?`, time.Now().Unix()-1, expired.ID); err != nil {
		t.Fatal(err)
	}
	actor, err := s.Authenticate(t.Context(), current.Secret, "session")
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := s.Sessions(t.Context(), actor)
	if err != nil || len(sessions) != 2 {
		t.Fatalf("sessions=%v err=%v", sessions, err)
	}
	for _, session := range sessions {
		if session.Current != (session.ID == current.ID) {
			t.Fatal("incorrect current session")
		}
	}
	if err := s.RevokeSession(t.Context(), actor, other.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("cross-user session revoked")
	}
	token, err := s.IssueToken(t.Context(), actor, user.ID, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeSession(t.Context(), actor, token.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("session endpoint revoked token")
	}
	if err := s.RevokeSession(t.Context(), actor, second.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(t.Context(), second.Secret, "session"); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("revoked session authenticates")
	}
	if _, err := s.Authenticate(t.Context(), current.Secret, "session"); err != nil {
		t.Fatal("revoking sibling logged out current session")
	}
	if err := s.RevokeSession(t.Context(), actor, current.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(t.Context(), current.Secret, "session"); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("self-revocation ineffective")
	}
}

func TestSessionAndOAuthHTTPRequireBrowserSession(t *testing.T) {
	s := testStore(t)
	u := testUser(t, s, "admin", Admin)
	token, err := s.IssueToken(t.Context(), principal(u), u.ID, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	browser := testSession(t, s, u)
	server := &Server{Store: s, AcceptOrigin: func(o string, _ *http.Request) bool { return o == "https://ui.example" }}
	mux := http.NewServeMux()
	server.Register(mux)
	gate := server.Wrap(mux)
	for _, path := range []string{"/sessions", "/oauth/links", "/oauth/settings"} {
		r := httptest.NewRequest("GET", "https://controller.example/api/v2/auth"+path, nil)
		r.Header.Set("Authorization", "Bearer "+token.Secret)
		w := httptest.NewRecorder()
		gate.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatalf("token accessed %s: %d", path, w.Code)
		}
	}
	for _, origin := range []string{"", "https://evil.example"} {
		r := httptest.NewRequest("POST", "https://controller.example/api/v2/auth/oauth/github/start", strings.NewReader("{}"))
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		gate.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal("start without trusted Origin")
		}
	}
	r := httptest.NewRequest("GET", "https://controller.example/api/v2/auth/sessions", nil)
	r.Header.Set("Authorization", "Session "+browser.Secret)
	w := httptest.NewRecorder()
	gate.ServeHTTP(w, r)
	if w.Code != 200 || strings.Contains(w.Body.String(), browser.Secret) || strings.Contains(w.Body.String(), "yu_") || !strings.Contains(w.Body.String(), `"current":true`) {
		t.Fatalf("unsafe sessions response: %d %s", w.Code, w.Body.String())
	}
}
