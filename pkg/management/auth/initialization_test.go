package auth

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func TestInitializationRestartExpiryAndPersistentCompletion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "management.db")
	open := func() (*storagesqlite.Store, *Store, *PasswordService) {
		t.Helper()
		db, err := storagesqlite.OpenManagement(t.Context(), path)
		if err != nil {
			t.Fatal(err)
		}
		s := NewStore(db.DB())
		p, err := NewPasswordService(t.Context(), s)
		if err != nil {
			t.Fatal(err)
		}
		return db, s, p
	}
	db, s, p := open()
	first, err := s.StartInitialization(t.Context())
	if err != nil || first.Secret == "" {
		t.Fatalf("initial code: %+v %v", first, err)
	}
	params, err := p.InitializationParameters(t.Context(), first.Secret)
	if err != nil {
		t.Fatal(err)
	}
	var stored []byte
	if err := s.db.QueryRowContext(t.Context(), `SELECT verifier FROM management_initialization`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte(first.Secret))
	if !bytes.Equal(stored, want[:]) || bytes.Contains(stored, []byte(first.Secret)) {
		t.Fatal("initialization secret stored in plaintext")
	}
	users, err := s.Users(t.Context())
	if err != nil || len(users) != 0 {
		t.Fatal("startup created an account before setup")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db, s, p = open()
	second, err := s.StartInitialization(t.Context())
	if err != nil || second.Secret == first.Secret {
		t.Fatal("restart did not rotate the unfinished setup")
	}
	if _, err := p.InitializationParameters(t.Context(), first.Secret); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("old code survived restart")
	}
	if err := p.CompleteInitialization(t.Context(), first.Secret, "owner", clientCredential(t, "password", params)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("old completion: %v", err)
	}
	if _, err := s.db.ExecContext(t.Context(), `UPDATE management_initialization SET expires_at=?`, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := p.InitializationParameters(t.Context(), second.Secret); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("expired setup accepted")
	}
	status, err := s.InitializationStatus(t.Context())
	if err != nil || !status.Required {
		t.Fatal("expiry completed initialization")
	}
	third, err := s.StartInitialization(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	params, err = p.InitializationParameters(t.Context(), third.Secret)
	if err != nil {
		t.Fatal(err)
	}
	credential := clientCredential(t, "password-é", params)
	if err := p.CompleteInitialization(t.Context(), third.Secret, "owner", "bad credential"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid credential: %v", err)
	}
	if err := p.CompleteInitialization(t.Context(), third.Secret, "owner", credential); err != nil {
		t.Fatal(err)
	}
	status, err = s.InitializationStatus(t.Context())
	if err != nil || status.Required || status.ExpiresAt != 0 {
		t.Fatalf("completed status: %+v %v", status, err)
	}
	if _, err := p.InitializationParameters(t.Context(), third.Secret); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("setup parameters still open after completion")
	}
	if err := p.CompleteInitialization(t.Context(), third.Secret, "intruder", credential); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("setup code was replayable")
	}
	session, err := p.Login(t.Context(), "owner", credential)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := s.Authenticate(t.Context(), session.Secret, "session")
	if err != nil || !owner.Allows(UsersManage) {
		t.Fatal("setup did not create an administrator")
	}
	// A password reset deliberately removes the current verifier. It must never
	// reopen setup, including after the process and database have been reopened.
	if _, err := s.ResetEnrollment(t.Context(), owner.UserID, owner.UserID); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, s, _ = open()
	defer db.Close()
	after, err := s.StartInitialization(t.Context())
	if err != nil || after.Secret != "" {
		t.Fatalf("reset/restart reopened setup: %+v %v", after, err)
	}
	status, err = s.InitializationStatus(t.Context())
	if err != nil || status.Required {
		t.Fatal("completion latch was lost")
	}
}

func TestInitializationConcurrentCompletionAndPendingBootstrap(t *testing.T) {
	s := testStore(t)
	pending, capability, err := s.CreateUser(t.Context(), "local", "admin", Admin, true)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewPasswordService(t.Context(), s)
	if err != nil {
		t.Fatal(err)
	}
	code, err := s.StartInitialization(t.Context())
	if err != nil || code.Secret == "" {
		t.Fatal("pending bootstrap incorrectly completed setup")
	}
	params, err := p.InitializationParameters(t.Context(), code.Secret)
	if err != nil {
		t.Fatal(err)
	}
	credential := clientCredential(t, "concurrent password", params)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Go(func() { results <- p.CompleteInitialization(t.Context(), code.Secret, "admin", credential) })
	}
	wg.Wait()
	close(results)
	var successes int
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("initialization winners: %d", successes)
	}
	users, err := s.Users(t.Context())
	if err != nil || len(users) != 1 || users[0].ID != pending.ID || !users[0].Enrolled {
		t.Fatal("pending account not completed atomically")
	}
	if _, err := p.EnrollmentParameters(t.Context(), capability.Secret); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("old pending enrollment survived setup")
	}
}

func TestInitializationHTTPRequiresCodeAndPreservesChannelPolicy(t *testing.T) {
	s := testStore(t)
	p, err := NewPasswordService(t.Context(), s)
	if err != nil {
		t.Fatal(err)
	}
	code, err := s.StartInitialization(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{Store: s, Passwords: p, AcceptOrigin: func(origin string, _ *http.Request) bool { return origin == "https://trusted.example" }}
	mux := http.NewServeMux()
	server.Register(mux)
	gate := server.Wrap(mux)
	call := func(method, path, auth, peer, origin, body string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.RemoteAddr = peer
		r.Header.Set("Authorization", auth)
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		gate.ServeHTTP(w, r)
		return w
	}
	status := call("GET", "/api/v2/auth/setup", "", "127.0.0.1:1", "", "")
	if status.Code != 200 || strings.Contains(status.Body.String(), code.Secret) || !strings.Contains(status.Body.String(), `"required":true`) {
		t.Fatal("unsafe setup status")
	}
	for _, tt := range []struct {
		path, auth, peer, origin string
		want                     int
	}{
		{"/api/v2/auth/setup/parameters", "", "127.0.0.1:1", "", 401},
		{"/api/v2/auth/setup/parameters", "Enrollment " + code.Secret, "127.0.0.1:1", "", 401},
		{"/api/v2/auth/setup/parameters?token=" + code.Secret, "Setup " + code.Secret, "127.0.0.1:1", "", 401},
		{"/api/v2/auth/setup/parameters", "Setup " + code.Secret, "192.0.2.1:1", "", 403},
		{"/api/v2/auth/setup/parameters", "Setup " + code.Secret, "127.0.0.1:1", "https://attacker.example", 403},
		{"/api/v2/auth/setup/parameters", "Setup " + code.Secret, "127.0.0.1:1", "https://trusted.example", 200},
	} {
		w := call("POST", tt.path, tt.auth, tt.peer, tt.origin, "{}")
		if w.Code != tt.want {
			t.Errorf("setup policy status=%d want=%d", w.Code, tt.want)
		}
	}
	credential := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	body := `{"login":"owner","clientCredential":"` + credential + `"}`
	w := call("POST", "/api/v2/auth/setup", "Setup "+code.Secret, "127.0.0.1:1", "", body)
	if w.Code != 200 {
		t.Fatalf("setup HTTP: %d %s", w.Code, w.Body.String())
	}
	status = call("GET", "/api/v2/auth/setup", "", "127.0.0.1:1", "", "")
	if !strings.Contains(status.Body.String(), `"required":false`) {
		t.Fatal("completed status missing")
	}
	if w := call("POST", "/api/v2/auth/setup", "Setup "+code.Secret, "127.0.0.1:1", "", body); w.Code != 401 {
		t.Fatal("HTTP setup remained open")
	}
}
